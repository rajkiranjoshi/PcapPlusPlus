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
#include <algorithm>

#define NUM_THREADS 4
#define MAX_NUM_THREADS 6
#define MTU_LENGTH 1500
#define DEFAULT_TTL 12


#define NUM_SEND_PACKETS 10000


std::vector<std::thread> workerThreads(NUM_THREADS);
bool stopSending;


void interruptHandler(int s){
    // printf("Caught signal %d\n",s);
    // stop capturing packets
    printf("\n Caught interrupt. Stopping sending threads...\n");

    stopSending = true;

    for(auto& t : workerThreads){
        t.join();
    }

}


pcpp::Packet* construct_send_packet(int packet_size){

    /* SENDER PKT CONSTRUCTION STARTS */

    pcpp::Packet* newSendPacket = new pcpp::Packet(packet_size);
    pcpp::MacAddress srcMac("3c:fd:fe:b7:e7:f5");
    pcpp::MacAddress dstMac("bb:bb:bb:bb:bb:bb");
    pcpp::IPv4Address srcIP(std::string("20.1.1.2"));
    pcpp::IPv4Address dstIP(std::string("40.1.1.2"));
    uint16_t srcPort = 37777;
    uint16_t dstPort = 7777;

    pcpp::EthLayer* newEthLayer = new pcpp::EthLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP); // 0x0800 -> IPv4
    pcpp::IPv4Layer* newIPv4Layer = new pcpp::IPv4Layer(srcIP, dstIP);
    newIPv4Layer->getIPv4Header()->timeToLive = DEFAULT_TTL;
    pcpp::UdpLayer* newUDPLayer = new pcpp::UdpLayer(srcPort, dstPort);
    pcpp::QmetadataLayer* newQmetadataLayer = new pcpp::QmetadataLayer(0);

    int length_so_far = newEthLayer->getHeaderLen() + newIPv4Layer->getHeaderLen() + 
                        newUDPLayer->getHeaderLen() + newQmetadataLayer->getHeaderLen();
    int payload_length = packet_size - length_so_far;

    // printf("SEND Header length before the payload is %d\n", length_so_far);
    
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
    pcpp::PayloadLayer* newPayLoadLayer = new pcpp::PayloadLayer(payload, payload_length, false);

    newSendPacket->addLayer(newEthLayer);
    newSendPacket->addLayer(newIPv4Layer);
    newSendPacket->addLayer(newUDPLayer);
    newSendPacket->addLayer(newQmetadataLayer);
    newSendPacket->addLayer(newPayLoadLayer);

    // compute the calculated fields
    newUDPLayer->computeCalculateFields();
    newUDPLayer->calculateChecksum(true);
    newIPv4Layer->computeCalculateFields(); // this takes care of the IPv4 checksum

    /* SENDER PKT CONSTRUCTION ENDS */

    return newSendPacket;
    
}


void send_func(int thread_id, pcpp::PcapLiveDevice* dev, pcpp::Packet** send_pkts_array, bool* stopSending){

    printf("\n[Thread %d] Starting packet sending ...\n", thread_id);
    
    while(!*stopSending){
        dev->sendPackets(send_pkts_array, NUM_SEND_PACKETS);
    }

    printf("\n[Thread %d] Stopping packet sending ...\n", thread_id);
}


int main(int argv, char* argc[]){


    if(NUM_THREADS > MAX_NUM_THREADS){
        printf("NUM_THREADS is greater than MAX_NUM_THREADS\n");
        exit(1);
    }

    /*
    int mtu_length;
    // See if packet size is provided as an argument
    if(argv == 2){
        mtu_length = atoi(argc[1]);
    }
    else{
        mtu_length = MTU_LENGTH;
    }
    printf("Using MTU LENGTH = %d\n", mtu_length);
    */


/*
    for(int i=0; i < 1000; i++){
        dev->sendPacket(&newPacket);
        usleep(500);
    }
    exit(0);
*/

    /********* SEND PACKETS PREPARATION - START *********/
    
    int send_pkts_sizes[NUM_SEND_PACKETS];
    FILE *fin = fopen("sender_pkt_sizes_cache.dat", "r");

    int pkt_size;
    int pkt_sizes[NUM_SEND_PACKETS];

    // read the packet sizes
    for(int i=0; i < NUM_SEND_PACKETS; i++){
        if(fscanf(fin,"%d",&pkt_size) == EOF){
            printf("EOF while reading pkt_size\n");
            return 1;
        }
        pkt_sizes[i] = pkt_size;
    }
    fclose(fin);

    
    pcpp::Packet* send_pkts_array[NUM_THREADS][NUM_SEND_PACKETS];


    for(int i=0; i < NUM_SEND_PACKETS; i++){
        pcpp::Packet* pkt_ptr;
        pkt_ptr = construct_send_packet(pkt_sizes[i]);
        for(int j=0; j < NUM_THREADS; j++){
            send_pkts_array[j][i] = pkt_ptr;
        }
        
    }

    // Shuffle the send_pkts_array for each thread
    for(int i=0; i < NUM_THREADS; i++){
        std::random_shuffle(&send_pkts_array[i][0], &send_pkts_array[i][NUM_SEND_PACKETS]);
    }

    

    /********* SEND PACKETS PREPARATION - END *********/



    /*********   DEVICE PREPARATION   *********/

    std::string IPaddr = "20.1.1.2";

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

    

    /*********   THREAD INITIALIZATION AND MANAGEMENT   *********/

    int vcpu_list[MAX_NUM_THREADS] = {10, 12, 14, 30, 32, 34};   // usable vcpu's for sender

    stopSending = false; // this is thread UNSAFE. 
                            // But in our case only the main thread writes. The worker threads simply read.

    for(int i=0;i < NUM_THREADS; i++){
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(vcpu_list[i], &cpuset); 

        
        workerThreads[i] = std::thread(send_func, i, dev, send_pkts_array[i], &stopSending);
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
