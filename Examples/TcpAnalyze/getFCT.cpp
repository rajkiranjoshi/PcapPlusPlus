#include "stdlib.h"
#include "PcapFileDevice.h"
#include "PlatformSpecificUtils.h"
#include "PcapPlusPlusVersion.h"
#include "SystemUtils.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "Packet.h"
#include "TcpLayer.h"
#include "PayloadLayer.h"
#include <arpa/inet.h>
#include <iostream>
#include <signal.h>
#include <string.h>
#include <sstream>
#include <map>
#include <algorithm> // for std::find
#include <iterator> // for std::begin, std::end
#include <unordered_map>
#include <sys/time.h>

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_RESET "\x1b[0m"

typedef struct timeval timeval;

typedef enum {
        SYN, RESYN, ACK_FOR_SYN, FIN, ACK_FOR_FIN, BLANK, DATA
} State;

// Global variables
FILE *fout;
uint16_t currSrcPort;
uint16_t countFlow = 0;

uint32_t nextExpectedSeqNumber;
uint32_t prevSeqNumber;
bool reTxDetected = false;
bool flowStarted = false;

bool randomDelay = false;

bool fastRetrans = false;


inline void detectReTransmission(uint32_t currSeqNumber, uint32_t tcpPayLoadLen, bool ack, bool syn, bool fin, bool psh){

	
	if (currSeqNumber < nextExpectedSeqNumber)
		reTxDetected = true;
	else if(currSeqNumber == prevSeqNumber){
		// check if this is FIN-ACK retransmission
		if(fin && ack && !psh)
			reTxDetected = true;
	}
			

	nextExpectedSeqNumber = currSeqNumber + tcpPayLoadLen;
	prevSeqNumber = currSeqNumber;
}


inline double tvToDouble(timeval tv){
	//static char floatValue[100];
    double floatValue = (double) ((tv.tv_sec * 1000000L + tv.tv_usec) / 1000000.0);
	//sprintf(floatValue, "%lf",(tv.tv_sec * 1000000L + tv.tv_usec) / 1000000.0);
    return floatValue;
}

void recordFlowTimes(timeval startTime, timeval threehandshakeTime, timeval transmissionTime, timeval FCTTime, uint16_t countFlow, bool randomDelay, bool fastRetrans)
{
    timeval connTime, dataTxTime, dataCompletionTime, FCT;
    
    timersub(&threehandshakeTime, &startTime, &connTime);
    timersub(&transmissionTime, &startTime, &dataTxTime);
    timersub(&FCTTime, &threehandshakeTime, &dataCompletionTime);
    timersub(&FCTTime, &startTime, &FCT);

    fprintf(fout,"%d %lf %lf %lf %lf %d %d %d %d\n", currSrcPort, tvToDouble(connTime), tvToDouble(dataCompletionTime), tvToDouble(FCT), tvToDouble(dataTxTime), int(reTxDetected), countFlow, int(randomDelay), int(fastRetrans));

}

int decideRandomDelay(timeval ackTime, timeval finTime, timeval threehandshakeTime, timeval firstDataTime)
{
    timeval delay;
    int result = 0;

    timersub(&finTime, &ackTime, &delay);
    if( tvToDouble(delay) > 0.005) //delay > 5ms
        result = 1;
    
    timersub(&firstDataTime,&threehandshakeTime,&delay);
    if( tvToDouble(delay) > 0.001) //delay > 1ms
        result = 1;


    return result;
}


inline void detectSynAckRTO(timeval synTime, timeval synAckTime){
    timeval delay;

    timersub(&synAckTime, &synTime, &delay);
    if( tvToDouble(delay) > 1.0) //delay > 1sec
        reTxDetected = true;

    // printf("SynTime: %lf, SynAck Time: %lf, SynAck Delay: %lf\n", tvToDouble(synTime), tvToDouble(synAckTime), tvToDouble(delay));
}


int main(int argc, char* argv[]){

    pcpp::AppName::init(argc, argv);

    std::string filename = "";
    std::string outputFile = "";

    if (argc != 4){
        printf("Usage: %s <pcap_file> <target_dst_IP> <output file>\n", argv[0]);
        exit(1);
    }
    filename = std::string(argv[1]);
    pcpp::IPv4Address targetDstIP(argv[2]);
    outputFile = std::string(argv[3]);

    
    // Open the output file
    fout = fopen(outputFile.c_str(), "w"); // fout is declared global to avoid passing around

    //printf("Filename is %s\n", filename.c_str());
    //printf("Target dstIP is %s\n", targetDstIP.toString().c_str());


    // use the IFileReaderDevice interface to automatically identify file type (pcap/pcap-ng)
    // and create an interface instance that both readers implement
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(filename.c_str());

    // verify that a reader interface was indeed created
    if (reader == NULL)
    {
        fprintf(stderr, "Cannot determine reader for file type\n");
        exit(1);
    }

    // open the reader for reading
    if (!reader->open())
    {
        fprintf(stderr, "Cannot open %s for reading\n",filename.c_str());
        exit(1);
    }


    
    pcpp::RawPacket rawPacket;
    pcpp::Packet parsedPacket;
    pcpp::IPv4Layer* ipv4layer;
    pcpp::iphdr* iphdr;
    pcpp::TcpLayer* tcplayer;
    pcpp::tcphdr *tcphdr;
   
    //uint16_t currSrcPort; 
    //uint16_t prevSrcPort;

    timeval startTime; 
    timeval threehandshakeTime;
    timeval transmissionTime;
    timeval FCTTime;
    timeval connTime, dataflowTime, FCT;
    timeval ackTime, finTime, synAckTime, firstDataTime;

    uint16_t totalLen;
    uint32_t ipHdrLen, tcpHdrLen, tcpPayLoadLen;
    uint32_t prevACKNo = -1;
    uint32_t currSeqNumber, ackNo;

    uint32_t currAckNo;
    uint32_t prevAck = 0;

    unsigned int frameNo = 1;
    unsigned int ackCount = 0;

    bool syn = false;
    bool ack = false;
    bool fin = false;
    bool data = false;
    bool rst = false;
    bool psh = false;


    State preState = BLANK;

/*   Logic-------for same srcPort & destination, we only see client side, assuming flow comes one by one, no mix packets

        state1 SYN; If this is first SYN(srcPort != previousSrcPort), startTime = rawPacket.getPacketTimeStamp(),
                    If this is retransmission SYN(srcPort = previousSrcPort), stop process this packet
        state2 ACK (and previous state is state1); Then, count it, threehandshakeTime = state2Time - startTime
        state3 FIN,,,count it transmissionTime = state3Time - state2Time
        state4 ACK (and previous state is state3),,,then, count it, FCT = state4Time - startTime
        default  go to next loop
*/
    while (reader->getNextPacket(rawPacket))
    {
        // parse the raw packet
        parsedPacket = pcpp::Packet(&rawPacket, pcpp::TCP); // TCP -> parse until this layer only
        ipv4layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
        tcplayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
        tcphdr = tcplayer->getTcpHeader();

        pcpp::IPv4Address currDstIP = ipv4layer->getDstIpAddress();
        pcpp::IPv4Address currSrcIP = ipv4layer->getSrcIpAddress();

        if(currDstIP == targetDstIP){ //only see client side

            syn = (bool)tcphdr->synFlag;
            ack = (bool)tcphdr->ackFlag;
            fin = (bool)tcphdr->finFlag;
            rst = (bool)tcphdr->rstFlag;
            psh = (bool)tcphdr->pshFlag;


            // seq / ack number
            ackNo = ntohl(tcphdr->ackNumber);
            currSeqNumber = ntohl(tcphdr->sequenceNumber);

            // Calculate the the tcp Payload length
        	totalLen = ntohs(ipv4layer->getIPv4Header()->totalLength);
            ipHdrLen = ipv4layer->getHeaderLen();
            tcpHdrLen = tcphdr->dataOffset * 4; // dataOffset tells tcp header length in terms of 4-byte words
            tcpPayLoadLen = totalLen - ipHdrLen - tcpHdrLen;

            // Decide if this is a data packet
            if(!ack)  // if the ACK flag is not set. Definitely not data pkt
            	data = false;
            else{ 
	            if(tcpPayLoadLen > 0)
	            	data = true;
	            else
	            	data = false;
            }

            // checking for reTransmissions
            if(flowStarted && !reTxDetected){
            	detectReTransmission(currSeqNumber, tcpPayLoadLen, ack, syn, fin, psh);
            }

            switch (preState){
                case BLANK: // start
                { 
                    if(syn && !ack){ //first syn
                        startTime = rawPacket.getPacketTimeStamp();
                        currSrcPort = ntohs(tcphdr->portSrc);
                        printf("[Frame %d] Flow started: %d \n", frameNo, currSrcPort);
                        printf("[Frame %d] Starttime: %lf\n", frameNo, tvToDouble(startTime));
                        preState = SYN;

                        // For the ReTx detection logic
                        currSeqNumber = ntohl(tcphdr->sequenceNumber);
                        nextExpectedSeqNumber = currSeqNumber + 1;
                        prevSeqNumber = currSeqNumber;
                        reTxDetected = false;
                        flowStarted = true;  // for handling multiple flows in the same pcap. If it is mix flows, this will fail
                        randomDelay = false; // handling random delay detection if multiple flows in the pcap
                        prevAck = 0;
                        fastRetrans = false;
                        break;
                    }
                    else if(ack && ackNo == (prevACKNo + 1)){ // ReTx of final ACK for teardown handshake
                        // we ignore this ReTx as FCT for previous flow is already recorded
                        preState = BLANK;
                        break;
                    }
                    else if(rst && !ack){
                        // we ignore this keep alive ack send from sender and rst the connection
                        preState = BLANK;
                        break;
                    }
                    else{
                    	printf(ANSI_COLOR_RED "BLANK: [Frame %d] expected SYN" ANSI_COLOR_RESET "\n",frameNo);
                    	break;
                    }
                }
                case SYN:
                {
                    if(syn && !ack){
                        preState = RESYN;
                        break;
                    }
                    if(ack && !syn && !data){
                        preState = ACK_FOR_SYN;
                        threehandshakeTime = rawPacket.getPacketTimeStamp();
                        prevACKNo = ackNo;
                        printf("[Frame %d] 3WH time: %lf\n", frameNo, tvToDouble(threehandshakeTime));
                        break;
                    }
                    else{
                    	printf(ANSI_COLOR_RED "SYN: [Frame %d] expected SYN(reTx) or ACK" ANSI_COLOR_RESET "\n",frameNo);
                    	break;
                    }
                }
                case RESYN:
                {
                	if(syn && !ack){//RESYN
                        preState = RESYN;
                        break;
                    }
                    else if(ack && !syn && !data){
                        preState = ACK_FOR_SYN;
                        threehandshakeTime = rawPacket.getPacketTimeStamp();
                        prevACKNo = ackNo;
                        printf("[Frame %d] 3WH time: %lf\n", frameNo, tvToDouble(threehandshakeTime));
                        break;
                    }
                    else{
                    	printf(ANSI_COLOR_RED "RESYN: [Frame %d] expected SYN(reTx) or ACK" ANSI_COLOR_RESET "\n",frameNo);
                    	break;
                    }
                }
                case ACK_FOR_SYN:
                {
                    if(data && ack && !fin){
                        preState = DATA;
                        firstDataTime = rawPacket.getPacketTimeStamp();
                        break;
                    }
                    else{
                    	printf(ANSI_COLOR_RED "ACK_FOR_SYN: [Frame %d] expected Data pkt" ANSI_COLOR_RESET "\n",frameNo);
                    	break;
                    }
                }
                case DATA:
                	if(data && ack && !fin){ //another data packet
                		preState = DATA; // state remains the same
                		break;
                	}
                    else if(fin && ack){ // FIN-ACK
                        transmissionTime = rawPacket.getPacketTimeStamp();
                        printf("[Frame %d]: transmissionTime: %lf\n", frameNo, tvToDouble(transmissionTime));
                        preState = FIN;
                        break;
                    }
                    else if(ack && !syn && !data && ackNo == prevACKNo){ // ACK_FOR_SYN(Retx)
                    	preState = DATA; // state remains the same
                        break;
                    }
                    else{ 
                    	printf(ANSI_COLOR_RED "DATA: [Frame %d] expected Data, FIN-ACK or ACK_FOR_SYN(reTx)" ANSI_COLOR_RESET "\n",frameNo);
                    	break;
                    }
                case FIN :
                {
                    if(ack && ackNo == (prevACKNo + 1)){ // final ACK for teardown handshake
                        FCTTime = rawPacket.getPacketTimeStamp();
                        printf("[Frame %d] FCTTime: %lf\n\n\n", frameNo, tvToDouble(FCTTime));
                        // IMP NOTE: this final ACK could be lost and may need to be ReTx
                        //           the following recordFlowTimes() doesn't include this ReTx time
                        recordFlowTimes(startTime, threehandshakeTime, transmissionTime, FCTTime, countFlow, randomDelay, fastRetrans);
                        preState = BLANK;
                        // prevACKNo = -1;

                        countFlow = countFlow +1;

                        // For reTx detection logic
                        flowStarted = false;
                        break;
                    }
                    else if(fin && ack){ //REFIN
                        preState = FIN;  // remains unchanged
                        break;
                    }
                    else if(data && ack && !fin){ // there can be data ReTx after FIN-ACK
                    	preState = FIN;  // remains unchanged
                    	break;
                    }
                    else if(ack && !syn && !data && ackNo == prevACKNo){ // ACK_FOR_SYN(Retx) (Observed from traces)
                    	// we ignore this spurious packet
                    	preState = FIN; // remains unchanged
                    	break;
                    }
                    else{
                        printf(ANSI_COLOR_RED "FIN: [Frame %d] expected LastACK, FIN-ACK(reTx), Data(reTx) or ACK_FOR_SYN(reTx)" ANSI_COLOR_RESET "\n",frameNo);
                        break;
                    }
                }
            }
        }
        frameNo++;

        if(currSrcIP == targetDstIP){ //see SERVER side
            syn = (bool)tcphdr->synFlag;
            ack = (bool)tcphdr->ackFlag;
            fin = (bool)tcphdr->finFlag;

            // printf("syn:%d, ack:%d, fin:%d\n",int(syn),int(ack),int(fin));

            if (syn && ack){
                synAckTime = rawPacket.getPacketTimeStamp();
            }
            else if(ack && !fin)
            {
                ackTime = rawPacket.getPacketTimeStamp();

                // fast retransmission detection
                currAckNo = ntohl(tcphdr->ackNumber);
                if(currAckNo == prevAck)
                    ackCount = ackCount + 1;
                else
                    ackCount = 0;

                if(ackCount == 3)
                    fastRetrans = true;
                    
                prevAck = currAckNo;                                      
            }
            else if(fin && ack){
                finTime = rawPacket.getPacketTimeStamp();
                randomDelay = decideRandomDelay(ackTime, finTime, threehandshakeTime, firstDataTime);
                detectSynAckRTO(startTime, synAckTime);   // startTime is SynTime
            }
        }
    } // end of the while loop

    reader->close();
    fclose(fout);

    return 0;
} // end of main()
