#include <stdio.h>
#include <malloc.h>

#include "stdlib.h"
#include "DpdkDeviceList.h"
#include "PcapLiveDeviceList.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "PayloadLayer.h"
#include "QmetadataLayer.h"
#include "PlatformSpecificUtils.h"
#include <unistd.h>  // for sleep() and usleep()
#include <thread>
#include <algorithm>

#define DEFAULT_TTL 12
#define NUM_OF_BURSTS 11
#define CORE_MASK 341  // in binary it is 101010101. Meaning core # 8,6,4, 2 and 0 would be given to DPDK
                       // core 0 would be used as the DPDK master core by default. To change this, need to 
                       // change DpdkDeviceList::initDpdk() in DpdkDeviceList.cpp and rebuild PcapPlusPlus

#define SEND_THREAD_CORE 18 // vcpu # (as shown by lstopo). This is the last core on socket #0
#define SEND_MTU_LENGTH 1500
#define SEND_RATE_SKIP_PACKETS 318 // helps reduce send rate to 5 Gbps. Old value 318 --> giving 3.72 for short run
#define SENDER_DPDK_PORT 1
#define DEFAULT_TTL 12

#define BURSTER_DPDK_PORT 2
#define BURST_THREAD_CORE 16  // vcpu # (as shown by lstopo). This is the second last core on socket #0
#define MBUFF_POOL_SIZE 2047  // (2^11 - 1) allow DPDK to hold these many packets in memory (at max).
                                // See "sending algorithm" in DpdkDevice.h

#define NUM_SEND_PACKETS 10000
#define NUM_THREADS 4
#define MAX_NUM_THREADS 6


using namespace pcpp;
using namespace std;

std::thread burstThread;

std::vector<std::thread> workerThreads(NUM_THREADS);
bool stopSending;



/********************** PACKET CONSTRUCTION - START **********************/

pcpp::Packet* construct_burst_packet(int packet_size){

    /* BURST PKT CONSTRUCTION STARTS */
    pcpp::Packet* newBurstPacket = new pcpp::Packet(packet_size);
    
    pcpp::MacAddress srcMacBurst("3c:fd:fe:b7:e7:f4");
    pcpp::MacAddress dstMacBurst("aa:aa:aa:aa:aa:aa");
    pcpp::IPv4Address srcIPBurst(std::string("10.1.1.2"));
    pcpp::IPv4Address dstIPBurst(std::string("40.1.1.2"));
    uint16_t srcPortBurst = 47777;
    uint16_t dstPortBurst = 7777;

    pcpp::EthLayer* newEthLayerBurst = new pcpp::EthLayer(srcMacBurst, dstMacBurst, PCPP_ETHERTYPE_IP); // 0x0800 -> IPv4
    pcpp::IPv4Layer* newIPv4LayerBurst = new pcpp::IPv4Layer(srcIPBurst, dstIPBurst);
    newIPv4LayerBurst->getIPv4Header()->timeToLive = DEFAULT_TTL;
    pcpp::UdpLayer* newUDPLayerBurst = new pcpp::UdpLayer(srcPortBurst, dstPortBurst);
    pcpp::QmetadataLayer* newQmetadataLayerBurst = new pcpp::QmetadataLayer(1);

    int length_so_far = newEthLayerBurst->getHeaderLen() + newIPv4LayerBurst->getHeaderLen() + 
                        newUDPLayerBurst->getHeaderLen() + newQmetadataLayerBurst->getHeaderLen();
    int payload_length = packet_size - length_so_far;

    // printf("BURST Header length before the payload is %d\n", length_so_far);
    
    uint8_t payloadBurst[payload_length];
    int datalen = 5;
    char burstdata[datalen] = {'B','U','R','S','T'};
    // Put the data values into the payload
    int j = 0;
    for(int i=0; i < payload_length; i++){
        payloadBurst[i] = (uint8_t) int(burstdata[j]);
        j = (j + 1) % datalen;
    }

    // construct the payload layer
    pcpp::PayloadLayer* newPayLoadLayerBurst = new pcpp::PayloadLayer(payloadBurst, payload_length, false);

    newBurstPacket->addLayer(newEthLayerBurst);
    newBurstPacket->addLayer(newIPv4LayerBurst);
    newBurstPacket->addLayer(newUDPLayerBurst);
    newBurstPacket->addLayer(newQmetadataLayerBurst);
    newBurstPacket->addLayer(newPayLoadLayerBurst);

    // compute the calculated fields
    newUDPLayerBurst->computeCalculateFields();
    newUDPLayerBurst->calculateChecksum(true);
    newIPv4LayerBurst->computeCalculateFields(); // this takes care of the IPv4 checksum
    return newBurstPacket;
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


/********************** PACKET CONSTRUCTION - END **********************/



void burst_func(DpdkDevice* dev, pcpp::Packet** burst_set[NUM_OF_BURSTS], int burst_size[NUM_OF_BURSTS], float sleeptime_inter_burst[NUM_OF_BURSTS]){

    usleep(100000); // sleep for 100ms to allow thread affinity to be set
    printf("[BURSTING Thread] Starting microbursts ...\n");

/*    int i=1;
    int n;
    const pcpp::Packet** burst_ptr = (const pcpp::Packet**) burst_set[i];
    n = dev->sendPackets(burst_ptr,burst_size[i]); // default Tx queue is 0
    printf("%d\n", n);*/

    int i = 0;
    //int packets[NUM_OF_BURSTS];
    while(i < NUM_OF_BURSTS)
    {
        const pcpp::Packet** burst_ptr = (const pcpp::Packet**) burst_set[i];
        dev->sendPackets(burst_ptr,burst_size[i]); // default Tx queue is 0
        //packets[i] = dev->sendPackets(burst_ptr,burst_size[i]); // default Tx queue is 0
        //printf("%d\n", packets[i]);
        usleep(sleeptime_inter_burst[i]); // sleeptime_inter_burst[i](us) gap among the bursts
        i++;      
    }
   

    printf("[BURSTING Thread] Stopping microbursts ...\n");
}


void send_func(int thread_id, pcpp::PcapLiveDevice* dev, pcpp::Packet** send_pkts_array, bool* stopSending){

    printf("\n[Thread %d] Starting packet sending ...\n", thread_id);
    
    while(!*stopSending){
        dev->sendPackets(send_pkts_array, NUM_SEND_PACKETS);
    }

    printf("\n[Thread %d] Stopping packet sending ...\n", thread_id);
}


int main()
{
    
    /********************** DPDK INITIALIZATION **********************/


    if(DpdkDeviceList::initDpdk(CORE_MASK, MBUFF_POOL_SIZE))
        printf("DPDK initialization completed successfully\n");
    else{
        printf("DPDK initialization failed!!\n");
        exit(1);
    }

    // go over all available DPDK devices and print info for each one
    printf("DPDK devices initialized:\n");
    vector<DpdkDevice*> deviceList = DpdkDeviceList::getInstance().getDpdkDeviceList();
    for (vector<DpdkDevice*>::iterator iter = deviceList.begin(); iter != deviceList.end(); iter++)
    {
        DpdkDevice* dev = *iter;
        printf("    Port #%d: MAC address='%s'; PCI address='%s'; PMD='%s'\n",
                dev->getDeviceId(),
                dev->getMacAddress().toString().c_str(),
                dev->getPciAddress().toString().c_str(),
                dev->getPMDName().c_str());
    }


    // Open the two DPDK ports

    DpdkDevice::LinkStatus linkstatus1,linkstatus2;


    DpdkDevice* burstPacketsTo = DpdkDeviceList::getInstance().getDeviceByPort(BURSTER_DPDK_PORT);

    if (burstPacketsTo != NULL && !burstPacketsTo->open())
    {
        printf("Could not open port#%d for sending packets\n", BURSTER_DPDK_PORT);
        exit(1);
    }
    else{
        printf("SENDING BURST TRAFFIC ON DPDK PORT %d\n", BURSTER_DPDK_PORT);
    }
    
    burstPacketsTo->getLinkStatus(linkstatus2);
    printf("The link on DPDK port %d is %s\n",BURSTER_DPDK_PORT,linkstatus2.linkUp?"UP":"Down");

    
    if(!linkstatus2.linkUp){
        printf("Exiting...\n");
        exit(1);
    }
    

    /********************** PCAP DEV INITIALIZATION **********************/

    if(NUM_THREADS > MAX_NUM_THREADS){
        printf("NUM_THREADS is greater than MAX_NUM_THREADS\n");
        exit(1);
    }

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


    /********* BURST PACKETS PREPARATION - START *********/

    FILE *fin1;
    float slptime;
    float sleeptime_inter_burst[NUM_OF_BURSTS];

    fin1 = fopen("sleeptime.txt","r");

    for(int i=0; i < NUM_OF_BURSTS; i++){
        if(fscanf(fin1,"%f",&slptime) == EOF){
            printf("EOF while reading num_pkts\n");
            return 1;
        }
        sleeptime_inter_burst[i] = slptime;
    }
    fclose(fin1);

    /*Get burst set*/
	FILE *fin;
	int num_pkts;
	int burst_size[NUM_OF_BURSTS];
	int* pkt_sizes[NUM_OF_BURSTS];

	fin = fopen("burst_set.txt","r");

	for(int i=0; i < NUM_OF_BURSTS; i++){
		if(fscanf(fin,"%d",&num_pkts) == EOF){
			printf("EOF while reading num_pkts\n");
			return 1;
		}
		burst_size[i] = num_pkts;
		pkt_sizes[i] = (int *) malloc(num_pkts * sizeof(int));
		for(int j=0; j < num_pkts; j++){
			fscanf(fin,"%d",&pkt_sizes[i][j]);
		}
	}
	fclose(fin);

	/*Construct packets for each bursts*/
    pcpp::Packet** pkt_burst;
    int number_pkts_in_burst, j;
    pcpp::Packet** burst_set[NUM_OF_BURSTS];
    pcpp::Packet burst_pkt;
    for(int i=0; i < NUM_OF_BURSTS; i++){
        number_pkts_in_burst = burst_size[i];
        j = 0;
        pkt_burst = (pcpp::Packet **) malloc(number_pkts_in_burst * sizeof(pcpp::Packet*));
        while(j < number_pkts_in_burst){

            pkt_burst[j] = construct_burst_packet(pkt_sizes[i][j]);

            j = j + 1;
        }
        burst_set[i] = pkt_burst;        
    }

    /********* BURST PACKETS PREPARATION - END *********/



    /********* SEND PACKETS PREPARATION - START *********/

    int send_pkts_sizes[NUM_SEND_PACKETS];
    FILE *fin_sender = fopen("sender_pkt_sizes_cache.dat", "r");

    int sender_pkt_size;
    int sender_pkt_sizes[NUM_SEND_PACKETS];

    // read the packet sizes
    for(int i=0; i < NUM_SEND_PACKETS; i++){
        if(fscanf(fin_sender,"%d",&sender_pkt_size) == EOF){
            printf("EOF while reading pkt_size\n");
            return 1;
        }
        sender_pkt_sizes[i] = sender_pkt_size;
    }
    fclose(fin_sender);

    
    pcpp::Packet* send_pkts_array[NUM_THREADS][NUM_SEND_PACKETS];


    for(int i=0; i < NUM_SEND_PACKETS; i++){
        pcpp::Packet* pkt_ptr;
        pkt_ptr = construct_send_packet(sender_pkt_sizes[i]);
        for(int j=0; j < NUM_THREADS; j++){
            send_pkts_array[j][i] = pkt_ptr;
        }
        
    }

    // Shuffle the send_pkts_array for each thread
    for(int i=0; i < NUM_THREADS; i++){
        std::random_shuffle(&send_pkts_array[i][0], &send_pkts_array[i][NUM_SEND_PACKETS]);
    }

    /********* SEND PACKETS PREPARATION - END *********/




    /********* THREAD INITIALIZATION & MANAGEMENT *********/
 
    /* SENDER THREAD(S) */
    int vcpu_list[MAX_NUM_THREADS] = {10, 12, 14, 30, 32, 34};   // usable vcpu's for sender

    stopSending = false; // this is thread UNSAFE. 
                            // But in our case only the main thread writes. The worker threads simply read.

    printf("###############    STARTING SENDER THREAD(S)    ###############\n");
    for(int i=0;i < NUM_THREADS; i++){
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(vcpu_list[i], &cpuset); 

        
        workerThreads[i] = std::thread(send_func, i, dev, send_pkts_array[i], &stopSending);
        int aff = pthread_setaffinity_np(workerThreads[i].native_handle(), sizeof(cpu_set_t), &cpuset);
    }


    printf("###############    STARTING BURSTER THREAD    ###############\n");
    /* BURSTER THREAD */
    cpu_set_t cpuset2;
    CPU_ZERO(&cpuset2);
    CPU_SET(BURST_THREAD_CORE, &cpuset2);
    burstThread = std::thread(burst_func, burstPacketsTo, burst_set, burst_size, sleeptime_inter_burst);

    burstThread.join();
    stopSending = true;
    for(int i=0; i < NUM_THREADS; i++){
        workerThreads[i].join();
    }

	return 0;
}
