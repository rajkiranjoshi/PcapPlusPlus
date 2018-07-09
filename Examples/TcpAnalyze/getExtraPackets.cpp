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


/*
int recordSeqNo(uint32_t sequenceNumber){
    totalPacketsSent++;

    uint32_t relativeSeqNumber = sequenceNumber - firstSeqNumber;

    
    if(relativeSeqNumber < prevRelativeSeqNumber){
        long int diff = prevRelativeSeqNumber - relativeSeqNumber;

        if(diff > IMPOSSIBLE_PKT_SIZE){
            era++;
        }
        
    }

    uint64_t key = era * MAX_UINT32 + relativeSeqNumber;

    auto it = pktCounts.find(key);
    if(it == pktCounts.end()){ // not found in the map
        pktCounts[key] = 1;
    }
    else{
        it->second += 1;
    }
    prevRelativeSeqNumber = relativeSeqNumber;
}

void printReTxPkts(){
    unsigned int numberOfReTxPackets = 0;

    //printf("#############################\n");
    for(auto it=pktCounts.begin(); it != pktCounts.end(); it++){
        if(it->second > 1 && it->first !=1){
            //printf("%lu: %u\n",it->first, it->second);
            numberOfReTxPackets += (it->second - 1);
        }
    }

    printf("%u %lu\n", numberOfReTxPackets, totalPacketsSent);
}

*/
int main(int argc, char* argv[]){

    pcpp::AppName::init(argc, argv);

    std::string filename = "";

    if (argc != 3){
        printf("Usage: %s <pcap_file> <target_dst_IP>\n", argv[0]);
        exit(1);
    }
    filename = std::string(argv[1]);
    pcpp::IPv4Address targetDstIP(argv[2]);
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
    
    uint16_t totalLen;
    uint32_t ipHdrLen, tcpHdrLen, tcpPayLoadLen;
    uint64_t totalPacketsReceived = 0;
    uint32_t firstSeqNumber;
    uint32_t nextExpectedSeqNumber;
    uint32_t extraPackets = 0;
    bool reorderingDetected = false;
    bool fin = false;

    // read off the first packet and record the firstSeqNumber
    reader->getNextPacket(rawPacket);
    totalPacketsReceived++;
    parsedPacket = pcpp::Packet(&rawPacket, pcpp::TCP); // TCP -> parse until this layer only
    tcplayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
    tcphdr = tcplayer->getTcpHeader();
    firstSeqNumber = ntohl(tcphdr->sequenceNumber);

    nextExpectedSeqNumber = firstSeqNumber + 1; // assuming first pkt is the SYN

    while (reader->getNextPacket(rawPacket))
    {
        // parse the raw packet
        parsedPacket = pcpp::Packet(&rawPacket, pcpp::TCP); // TCP -> parse until this layer only
        ipv4layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
        tcplayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
        tcphdr = tcplayer->getTcpHeader();

        uint32_t currSeqNumber = ntohl(tcphdr->sequenceNumber);

        pcpp::IPv4Address currDstIP = ipv4layer->getDstIpAddress();

        if(currDstIP == targetDstIP){
            totalPacketsReceived++;

            //printf("nextExpectedSeqNumber:%u currSeqNumber:%u\n", nextExpectedSeqNumber -firstSeqNumber, currSeqNumber - firstSeqNumber);
            if(currSeqNumber < nextExpectedSeqNumber){
                extraPackets++;
                // printf("EXTRA PKT: SeqNo = %u\n", currSeqNumber - firstSeqNumber);
                continue;
            }
            else if (currSeqNumber > nextExpectedSeqNumber){ // there is reordering
                /*
                printf("############# ALERT #############\n");
                printf("nextExpectedSeqNumber:%u currSeqNumber:%u\n", nextExpectedSeqNumber -firstSeqNumber, currSeqNumber - firstSeqNumber);
                printf("First reordered packet has relative SeqNo = %u\n", currSeqNumber - firstSeqNumber);
                */
                reorderingDetected = true;
                break;
            }

            // check if FIN pkt. If so stop the processing
            fin = (bool)tcphdr->finFlag;
            if(fin)
                break;

            // calculate the nextExpectedSeqNumber
            totalLen = ntohs(ipv4layer->getIPv4Header()->totalLength);
            ipHdrLen = ipv4layer->getHeaderLen();
            tcpHdrLen = tcphdr->dataOffset * 4; // dataOffset tells tcp header length in terms of 4-byte words
            tcpPayLoadLen = totalLen - ipHdrLen - tcpHdrLen;
            nextExpectedSeqNumber = currSeqNumber + tcpPayLoadLen;
            //printf("Seq:%u Len:%u\n",currSeqNumber - firstSeqNumber, tcpPayLoadLen);
            //std::getchar();
        }
    } // end of the while loop

    reader->close();

    printf("%u %s\n", extraPackets, reorderingDetected? "Yes":"No");


    return 0;
} // end of main()
