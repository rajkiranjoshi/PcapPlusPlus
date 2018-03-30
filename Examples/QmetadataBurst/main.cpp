#include "stdlib.h"
#include "PcapFileDevice.h"
#include "DpdkDeviceList.h"
#include "PlatformSpecificUtils.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "PayloadLayer.h"
#include "QmetadataLayer.h"
#include "Logger.h"
#include <iostream>
#include <thread>
#include <signal.h>
#include <unistd.h>  // for sleep() and usleep()

using namespace std::chrono;
using namespace pcpp;
using namespace std;

#define MBUFF_POOL_SIZE 1023  // (2^10 - 1) allow DPDK to hold these many packets in memory (at max).
                              // See "sending algorithm" in DpdkDevice.h
#define CORE_MASK 341  // in binary it is 101010101. Meaning core # 8,6,4, 2 and 0 would be given to DPDK
                       // core 0 would be used as the DPDK master core by default. To change this, need to 
                       // change DpdkDeviceList::initDpdk() in DpdkDeviceList.cpp and rebuild PcapPlusPlus

#define SEND_THREAD_CORE 18 // vcpu # (as shown by lstopo). This is the last core on socket #0
#define SEND_MTU_LENGTH 1500
#define SEND_RATE_SKIP_PACKETS 318 // helps reduce send rate to 5 Gbps. Old value 318 --> giving 3.72 for short run
#define SENDER_DPDK_PORT 1
#define DEFAULT_TTL 12

#define BURSTER_DPDK_PORT 0
#define BURST_THREAD_CORE 16  // vcpu # (as shown by lstopo). This is the second last core on socket #0
#define BURST_MTU_LENGTH 1500
#define NUM_PKTS_IN_BURST 42
#define NUM_BURSTS 5  // the bursts are separated by 1ms gap

std::thread sendThread, burstThread;
bool stopSending;

void interruptHandler(int s){
    
    printf("\nCaught interrupt. Stopping the threads ...\n");

    stopSending = true;
    burstThread.join();
    sendThread.join();  
}


void burst_func(DpdkDevice* dev, pcpp::Packet parsedPacket){

    usleep(100000); // sleep for 100ms to allow thread affinity to be set
    printf("[BURSTING Thread] Starting microbursts ...\n");

    pcpp::Packet* pkt_burst[NUM_PKTS_IN_BURST];
    std::fill_n(pkt_burst, NUM_PKTS_IN_BURST, &parsedPacket);

    const pcpp::Packet** burst_ptr = (const pcpp::Packet**) pkt_burst;    

    for(int i=0; i < NUM_BURSTS; i++){
    // while(!stopSending)
        dev->sendPackets(burst_ptr, NUM_PKTS_IN_BURST); // default Tx queue is 0
        usleep(1000); // 1 ms gap between the bursts
    }

    printf("[BURSTING Thread] Stopping microbursts ...\n");
}


void send_func(DpdkDevice* dev, pcpp::Packet parsedPacket, bool* stopSending){

    printf("[SENDING Thread] Starting test traffic ...\n");

    pcpp::QmetadataLayer* qmetadatalayer = parsedPacket.getLayerOfType<pcpp::QmetadataLayer>();

    int i = 0;
    while(!*stopSending){
        if(i == 0){
            dev->sendPacket(parsedPacket,0);
        }
        i = (i+1) % SEND_RATE_SKIP_PACKETS;
    }

    printf("[SENDING Thread] Stopping test traffic  ...\n");
}


int main(int argv, char* argc[]){

    
    // LoggerPP::getInstance().setAllModlesToLogLevel(LoggerPP::Debug);

    /********************** PACKET CONSTRUCTION **********************/

    /* SENDER PKT CONSTRUCTION STARTS */
    pcpp::Packet newSendPacket(SEND_MTU_LENGTH);
    pcpp::MacAddress srcMac("3c:fd:fe:b7:e7:f5");
    pcpp::MacAddress dstMac("bb:bb:bb:bb:bb:bb");
    pcpp::IPv4Address srcIP(std::string("20.1.1.2"));
    pcpp::IPv4Address dstIP(std::string("40.1.1.2"));
    uint16_t srcPort = 37777;
    uint16_t dstPort = 7777;

    pcpp::EthLayer newEthLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP); // 0x0800 -> IPv4
    pcpp::IPv4Layer newIPv4Layer(srcIP, dstIP);
    newIPv4Layer.getIPv4Header()->timeToLive = DEFAULT_TTL;
    pcpp::UdpLayer newUDPLayer(srcPort, dstPort);
    pcpp::QmetadataLayer newQmetadataLayer(1);

    int length_so_far = newEthLayer.getHeaderLen() + newIPv4Layer.getHeaderLen() + 
                        newUDPLayer.getHeaderLen() + newQmetadataLayer.getHeaderLen();
    int payload_length = SEND_MTU_LENGTH - length_so_far;

    printf("SEND Header length before the payload is %d\n", length_so_far);
    
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

    newSendPacket.addLayer(&newEthLayer);
    newSendPacket.addLayer(&newIPv4Layer);
    newSendPacket.addLayer(&newUDPLayer);
    newSendPacket.addLayer(&newQmetadataLayer);
    newSendPacket.addLayer(&newPayLoadLayer);

    // compute the calculated fields
    newUDPLayer.computeCalculateFields();
    newUDPLayer.calculateChecksum(true);
    newIPv4Layer.computeCalculateFields(); // this takes care of the IPv4 checksum

    /* SENDER PKT CONSTRUCTION ENDS */


    /* BURST PKT CONSTRUCTION STARTS */
    pcpp::Packet newBurstPacket(BURST_MTU_LENGTH);
    pcpp::MacAddress srcMacBurst("3c:fd:fe:b7:e7:f4");
    pcpp::MacAddress dstMacBurst("aa:aa:aa:aa:aa:aa");
    pcpp::IPv4Address srcIPBurst(std::string("10.1.1.2"));
    pcpp::IPv4Address dstIPBurst(std::string("40.1.1.2"));
    uint16_t srcPortBurst = 47777;
    uint16_t dstPortBurst = 7777;

    pcpp::EthLayer newEthLayerBurst(srcMacBurst, dstMacBurst, PCPP_ETHERTYPE_IP); // 0x0800 -> IPv4
    pcpp::IPv4Layer newIPv4LayerBurst(srcIPBurst, dstIPBurst);
    newIPv4LayerBurst.getIPv4Header()->timeToLive = DEFAULT_TTL;
    pcpp::UdpLayer newUDPLayerBurst(srcPortBurst, dstPortBurst);
    pcpp::QmetadataLayer newQmetadataLayerBurst(1);

    length_so_far = newEthLayerBurst.getHeaderLen() + newIPv4LayerBurst.getHeaderLen() + 
                        newUDPLayerBurst.getHeaderLen() + newQmetadataLayerBurst.getHeaderLen();
    payload_length = BURST_MTU_LENGTH - length_so_far;

    printf("BURST Header length before the payload is %d\n", length_so_far);
    
    uint8_t payloadBurst[payload_length];
    datalen = 5;
    char burstdata[datalen] = {'B','U','R','S','T'};
    // Put the data values into the payload
    j = 0;
    for(int i=0; i < payload_length; i++){
        payloadBurst[i] = (uint8_t) int(burstdata[j]);
        j = (j + 1) % datalen;
    }

    // construct the payload layer
    pcpp::PayloadLayer newPayLoadLayerBurst(payloadBurst, payload_length, false);

    newBurstPacket.addLayer(&newEthLayerBurst);
    newBurstPacket.addLayer(&newIPv4LayerBurst);
    newBurstPacket.addLayer(&newUDPLayerBurst);
    newBurstPacket.addLayer(&newQmetadataLayerBurst);
    newBurstPacket.addLayer(&newPayLoadLayerBurst);

    // compute the calculated fields
    newUDPLayerBurst.computeCalculateFields();
    newUDPLayerBurst.calculateChecksum(true);
    newIPv4LayerBurst.computeCalculateFields(); // this takes care of the IPv4 checksum


    /* BURST PKT CONSTRUCTION ENDS */


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
    
    DpdkDevice* sendPacketsTo = DpdkDeviceList::getInstance().getDeviceByPort(SENDER_DPDK_PORT);
    if (sendPacketsTo != NULL && !sendPacketsTo->open())
    {
        printf("Could not open port#%d for sending packets\n", SENDER_DPDK_PORT);
        exit(1);
    }
    else{
        printf("SENDING TEST TRAFFIC ON DPDK PORT %d\n", SENDER_DPDK_PORT);
    }
    
    sendPacketsTo->getLinkStatus(linkstatus1);
    printf("The link on DPDK port %d is %s\n",SENDER_DPDK_PORT,linkstatus1.linkUp?"UP":"Down");


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

    
    if(!linkstatus1.linkUp || !linkstatus2.linkUp){
        printf("Exiting...\n");
        exit(1);
    }

    


    /********* THREAD INITIALIZATION & MANAGEMENT *********/
 
    /* SENDER THREAD */
    cpu_set_t cpuset1;
    CPU_ZERO(&cpuset1);
    CPU_SET(SEND_THREAD_CORE, &cpuset1); 

    stopSending = false; // this is thread UNSAFE. 
                         // But in our case only the main thread writes. The sender thread simply reads.
    
    sendThread = std::thread(send_func, sendPacketsTo, newSendPacket, &stopSending);
    int aff = pthread_setaffinity_np(sendThread.native_handle(), sizeof(cpu_set_t), &cpuset1);
    printf("Sending thread now running on vcpu #%d\n", SEND_THREAD_CORE);

    sleep(1);
    printf("Sleeping for 10s before starting the BURST thread\n");
    sleep(10);
    printf("\n### Start the packet capture at receiver NOW ###\n");
    printf("Press any key to continue . . .\n");
    getchar();

    /* BURSTER THREAD */
    cpu_set_t cpuset2;
    CPU_ZERO(&cpuset2);
    CPU_SET(BURST_THREAD_CORE, &cpuset2);
    
    burstThread = std::thread(burst_func, burstPacketsTo, newBurstPacket);
    aff = pthread_setaffinity_np(burstThread.native_handle(), sizeof(cpu_set_t), &cpuset2);
    printf("Bursting thread now running on vcpu #%d\n", BURST_THREAD_CORE);


    
    /********* INTERRUPT HANDLING *********/
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = interruptHandler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);

    
    /********* NORMAL SHUTTING DOWN SEQUENCE *********/
    burstThread.join();
    printf("Sleeping for 500 ms before stopping the SEND thread\n");
    usleep(500000); // 500ms
    stopSending = true;
    sendThread.join();

    // pause();


  
    return 0;
} // end of main()