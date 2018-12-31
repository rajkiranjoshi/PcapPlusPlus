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
   
    uint16_t currSrcPort; 
    uint16_t prevSrcPort = -1; 
    bool syn = false;
    bool ack = false;

    while (reader->getNextPacket(rawPacket))
    {
        // parse the raw packet
        parsedPacket = pcpp::Packet(&rawPacket, pcpp::TCP); // TCP -> parse until this layer only
        ipv4layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
        tcplayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
        tcphdr = tcplayer->getTcpHeader();

        pcpp::IPv4Address currDstIP = ipv4layer->getDstIpAddress();

        if(currDstIP == targetDstIP){
            // check if FIN pkt. If so stop the processing
            syn = (bool)tcphdr->synFlag;
            ack = (bool)tcphdr->ackFlag; // not needed to check since dstIP used to check direction
            if(syn && !ack){ // it is a syn packet
                currSrcPort = ntohs(tcphdr->portSrc);
                if(currSrcPort != prevSrcPort){
                    printf("%u\n",currSrcPort);                       
                }
                prevSrcPort = currSrcPort;
            }

        }
    } // end of the while loop

    reader->close();

    return 0;
} // end of main()
