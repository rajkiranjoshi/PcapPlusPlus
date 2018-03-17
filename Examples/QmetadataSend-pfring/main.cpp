#include "stdlib.h"
#include "PfRingDevice.h"
#include "PfRingDeviceList.h"
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

#define NUM_THREADS 1
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


void send_func(int thread_id, pcpp::PfRingDevice* dev, pcpp::Packet parsedPacket, bool* stopSending){

    printf("\n[Thread %d] Starting packet sending ...\n", thread_id);

    // high_resolution_clock::time_point t1 = high_resolution_clock::now();
    
    //long long num_packets = 10000000; // 40000000; 
    //for(long long i=0; i < num_packets; i++){

    pcpp::QmetadataLayer* qmetadatalayer = parsedPacket.getLayerOfType<pcpp::QmetadataLayer>();

    int i = 0;
    //long int i = 0;
    while(!*stopSending){
    //while(i < 10000000){
        // qmetadatalayer->setSeqNo(i);
        dev->sendPacket(parsedPacket);
        // i++;
    }

    printf("\n[Thread %d] Stopping packet sending ...\n", thread_id);
}


int main(int argv, char* argc[]){

    // construct the required packet
    pcpp::Packet newPacket(MTU_LENGTH);
    pcpp::MacAddress srcMac("3c:fd:fe:b7:e7:f4");
    pcpp::MacAddress dstMac("aa:aa:aa:aa:aa:aa");
    pcpp::IPv4Address srcIP(std::string("10.1.1.2"));
    pcpp::IPv4Address dstIP(std::string("40.1.1.2"));
    uint16_t srcPort = 37777;
    uint16_t dstPort = 7777;

    pcpp::EthLayer newEthLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP); // 0x0800 -> IPv4
    pcpp::IPv4Layer newIPv4Layer(srcIP, dstIP);
    newIPv4Layer.getIPv4Header()->timeToLive = DEFAULT_TTL;
    pcpp::UdpLayer newUDPLayer(srcPort, dstPort);
    pcpp::QmetadataLayer newQmetadataLayer(0);

    // newQmetadataLayer.getQmetadataHeader()->enqTimestamp=htonl(1);
    // newQmetadataLayer.getQmetadataHeader()->markBit=htons(1);
    // newQmetadataLayer.getQmetadataHeader()->enqQdepth=htonl(2);
    // newQmetadataLayer.getQmetadataHeader()->deqQdepth=htonl(3);
    // newQmetadataLayer.getQmetadataHeader()->deqTimedelta=htonl(4);

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

    std::string sendPacketsToIfaceName = "enp5s0f0";

    pcpp::PfRingDevice* sendPacketsToIface = pcpp::PfRingDeviceList::getInstance().getPfRingDeviceByName(sendPacketsToIfaceName);

    if (sendPacketsToIface == NULL){
        printf("Could not find PF_RING device '%s'\n", sendPacketsToIfaceName.c_str());
        exit(1);
    }

    // open the PF_RING device
    if (sendPacketsToIface != NULL && !sendPacketsToIface->open()){
        printf("Couldn't open PF_RING device '%s' for sending matched packets", sendPacketsToIface->getDeviceName().c_str());
        exit(1);
    }

/*
    for(int i=0; i < 5; i++)
    {
        newQmetadataLayer.setSeqNo(i);
        sendPacketsToIface->sendPacket(newPacket);
        PCAP_SLEEP(1);
    }
*/
    
    for(int i=0;i < NUM_THREADS; i++){
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(i, &cpuset); 

        stopSending[i] = false; // this is thread UNSAFE. 
                                // But in our case only the main thread writes. The worker threads simply read.
        workerThreads[i] = std::thread(send_func, i, sendPacketsToIface, newPacket, &stopSending[i]);
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
