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
#include <thread>
#include <signal.h>

#define NUM_THREADS 2
#define MTU_LENGTH 1500
#define DEFAULT_TTL 12

std::vector<std::thread> workerThreads(NUM_THREADS);
bool stopSending[NUM_THREADS];

void interruptHandler(int s){
    // printf("Caught signal %d\n",s);
    // stop capturing packets
    printf("\n Caught interrupt. Stopping sending threads...\n");

    for(int i=0; i < NUM_THREADS; i++){
        stopSending[i] = true;
    }

    for(auto& t : workerThreads){
        t.join();
    }

}


void send_func(int thread_id, pcpp::PcapLiveDevice* dev, pcpp::Packet parsedPacket, bool* stopSending){

    printf("\n[Thread %d] Starting packet sending ...\n", thread_id);


    pcpp::QmetadataLayer* qmetadatalayer = parsedPacket.getLayerOfType<pcpp::QmetadataLayer>();

    
    while(!*stopSending){
        dev->sendPacket(&parsedPacket);
    }

    printf("\n[Thread %d] Stopping packet sending ...\n", thread_id);
}


int main(int argv, char* argc[]){

    // construct the required packet
    pcpp::Packet newPacket(MTU_LENGTH);
    pcpp::MacAddress srcMac("3c:fd:fe:b7:e7:f4");
    pcpp::MacAddress dstMac("aa:aa:aa:aa:aa:aa");
    pcpp::IPv4Address srcIP(std::string("20.1.1.2"));
    pcpp::IPv4Address dstIP(std::string("40.1.1.2"));
    uint16_t srcPort = 37777;
    uint16_t dstPort = 7777;

    pcpp::EthLayer newEthLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP); // 0x0800 -> IPv4
    pcpp::IPv4Layer newIPv4Layer(srcIP, dstIP);
    newIPv4Layer.getIPv4Header()->timeToLive = DEFAULT_TTL;
    pcpp::UdpLayer newUDPLayer(srcPort, dstPort);
    pcpp::QmetadataLayer newQmetadataLayer(0);

    int length_so_far = newEthLayer.getHeaderLen() + newIPv4Layer.getHeaderLen() + 
                        newUDPLayer.getHeaderLen() + newQmetadataLayer.getHeaderLen();
    int payload_length = MTU_LENGTH - length_so_far;

    printf("Header length before the payload is %d\n", length_so_far);
    
    uint8_t payload[payload_length];
    int datalen = 4;
    char data[datalen] = {'D','A','T','A'};
    // Put the data values into the payload
    int j = 0;
    for(int i=0; i < payload_length; i++){
        payload[i] = (uint8_t) int(data[j]);
        j = (j + 1) % datalen;
    }

    // construct the payload layer
    pcpp::PayloadLayer newPayLoadLayer(payload, payload_length, false);

    newPacket.addLayer(&newEthLayer);
    newPacket.addLayer(&newIPv4Layer);
    newPacket.addLayer(&newUDPLayer);
    newPacket.addLayer(&newQmetadataLayer);
    newPacket.addLayer(&newPayLoadLayer);

    // compute the calculated fields
    newUDPLayer.computeCalculateFields();
    newUDPLayer.calculateChecksum(true);
    newIPv4Layer.computeCalculateFields(); // this takes care of the IPv4 checksum

    std::string IPaddr = "10.1.1.2";

    pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(IPaddr.c_str());

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

/*    for(int i=0; i < 5; i++){
        dev->sendPacket(&newPacket);
        PCAP_SLEEP(1);
    }*/
    
    for(int i=0;i < NUM_THREADS; i++){
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(i, &cpuset); 

        stopSending[i] = false; // this is thread UNSAFE. 
                                // But in our case only the main thread writes. The worker threads simply read.
        workerThreads[i] = std::thread(send_func, i, dev, newPacket, &stopSending[i]);
        int aff = pthread_setaffinity_np(workerThreads[i].native_handle(), sizeof(cpu_set_t), &cpuset);
    }


    // code to handle keyboard interrupt
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = interruptHandler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);

    pause();

    

    return 0;
} // end of main()
