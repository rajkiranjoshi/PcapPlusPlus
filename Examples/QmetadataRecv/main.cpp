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

#define MTU_LENGTH 1500
#define DEFAULT_TTL 12  

pcpp::PcapLiveDevice* dev;

void my_handler(int s){
    // printf("Caught signal %d\n",s);
    // stop capturing packets
    printf("Stopping packet capture...\n");
    dev->stopCapture();
    exit(1);
}

/**
* A callback function for the async capture which is called each time a packet is captured
*/
static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
    
    // parse the raw packet
    pcpp::Packet parsedPacket(packet, pcpp::QMETADATA); // QMETADATA -> parse until this layer only
                                                        
    pcpp::QmetadataLayer* qmlayer = parsedPacket.getLayerOfType<pcpp::QmetadataLayer>();

    std::cout << qmlayer->toString() << "\n";
}


int main(int argv, char* argc[]){

    std::string IPaddr = "20.1.1.2";

    dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(IPaddr.c_str());

    if (dev == NULL){
        printf("Could not find the interface with IP '%s'\n", IPaddr.c_str());
        exit(1);
    }

    // before capturing packets let's print some info about this interface
    printf("Interface info:\n");
    // get interface name
    printf("   Interface name:        %s\n", dev->getName());
    // get interface description
    printf("   Interface description: %s\n", dev->getDesc());
    // get interface MAC address
    printf("   MAC address:           %s\n", dev->getMacAddress().toString().c_str());
    // get default gateway for interface
    printf("   Default gateway:       %s\n", dev->getDefaultGateway().toString().c_str());
    // get interface MTU
    printf("   Interface MTU:         %d\n", dev->getMtu());
    // get DNS server if defined for this interface
    if (dev->getDnsServers().size() > 0)
        printf("   DNS server:            %s\n", dev->getDnsServers().at(0).toString().c_str());

    // open the device before start capturing/sending packets
    if (!dev->open())
    {
        printf("Cannot open device\n");
        exit(1);
    }

    printf("\nStarting async capture...\n");

    void* dummy_cookie;
    dev->startCapture(onPacketArrives, dummy_cookie);
    
    // code to handle keyboard interrupt
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = my_handler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);

    pause();

    return 0;
} // end of main()
