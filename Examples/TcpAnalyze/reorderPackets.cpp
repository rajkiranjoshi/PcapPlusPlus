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
#include <iterator> // for std::begin, std::end
#include <unordered_map>

#define TOTAL_PKTS 20


int main(int argc, char* argv[]){

    pcpp::AppName::init(argc, argv);

    std::string filename = "";

    if (argc != 3){
        printf("Usage: %s <pcap_file> <target_dst_IP>\n", argv[0]);
        exit(1);
    }
    filename = std::string(argv[1]);
    pcpp::IPv4Address targetDstIP(argv[2]);

    // create the output filename
    int dotIndex = filename.find_last_of("."); 
    std::string outputFile = filename.substr(0, dotIndex) + "_reordered.pcap";

    //printf("Output filename is %s\n", outputFile.c_str());

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


    pcpp::RawPacket pktList[TOTAL_PKTS];
    pcpp::RawPacket rawPacket;
    pcpp::Packet parsedPacket;
    pcpp::IPv4Layer* ipv4layer;
    int i = 0;

    while (i < TOTAL_PKTS){

        // read the packet
        reader->getNextPacket(rawPacket);
        // parse the raw packet
        parsedPacket = pcpp::Packet(&rawPacket, pcpp::TCP); // TCP -> parse until this layer only
        ipv4layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    
        pcpp::IPv4Address currDstIP = ipv4layer->getDstIpAddress();

        if(currDstIP == targetDstIP){
            pktList[i] = rawPacket;
            i++;
        }

    } // end of the while loop

    reader->close();

    pcpp::PcapFileWriterDevice writer(outputFile.c_str(),pcpp::LINKTYPE_ETHERNET);

    if (!writer.open())
    {
        fprintf(stderr, "Cannot open %s for writing\n",outputFile.c_str());
        exit(1);
    }

    printf("Writer opened successfully\n");

    // write the first 10 packets
    for(int i=0; i < 10; i++){
        writer.writePacket(pktList[i]);
    }

    // reorder the next 5 packets
    for(int i=14; i > 9; i--){
        writer.writePacket(pktList[i]);   
    }

    // write the rest of the packets in order
    for(int i=15; i < TOTAL_PKTS; i++){
        writer.writePacket(pktList[i]);
    }    

    writer.close();


    return 0;
} // end of main()
