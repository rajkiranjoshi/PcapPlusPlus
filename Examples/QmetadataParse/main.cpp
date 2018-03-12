#include "stdlib.h"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include "PlatformSpecificUtils.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "PayloadLayer.h"
#include "QmetadataLayer.h"
#include <arpa/inet.h>
#include <iostream>
#include <signal.h>
#include <string.h>
#include <sstream>

int main(int argv, char* argc[]){

    if(argv != 2){
        printf("Takes exactly one argument - the pcap file to parse\n");
        exit(1);
    }

    std::string filename(argc[1]);

    // use the IFileReaderDevice interface to automatically identify file type (pcap/pcap-ng)
    // and create an interface instance that both readers implement
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(filename.c_str());

    // verify that a reader interface was indeed created
    if (reader == NULL)
    {
        printf("Cannot determine reader for file type\n");
        exit(1);
    }

    // open the reader for reading
    if (!reader->open())
    {
        printf("Cannot open %s for reading\n",filename.c_str());
        exit(1);
    }

    // the packet container
    pcpp::RawPacket rawPacket;
    bool base_initialized = false;
    long int base_sec;
    long int base_usec;
    
    while (reader->getNextPacket(rawPacket))
    {
        struct timeval timestamp;
        timestamp = rawPacket.getPacketTimeStamp();

        if(!base_initialized){
            base_sec = timestamp.tv_sec;
            base_usec = timestamp.tv_usec;

            base_initialized = true;
        }

        long int sec = timestamp.tv_sec - base_sec;
        long int usec = timestamp.tv_usec - base_usec;
        long int ts = sec * 1000000L + usec;

        // parse the raw packet
        pcpp::Packet parsedPacket(&rawPacket, pcpp::QMETADATA); // QMETADATA -> parse until this layer only
                                                        
        pcpp::QmetadataLayer* qmlayer = parsedPacket.getLayerOfType<pcpp::QmetadataLayer>();
        
        std::cout << ts << " " << qmlayer->toString() << "\n";
    }

    reader->close();

    return 0;
} // end of main()
