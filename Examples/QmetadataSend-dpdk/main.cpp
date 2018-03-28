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

using namespace std::chrono;
using namespace pcpp;
using namespace std;

#define MBUFF_POOL_SIZE 1023  // (2^10 - 1) allow DPDK to hold these many packets in memory (at max).
                              // See "sending algorithm" in DpdkDevice.h
#define CORE_MASK 341  // in binary it is 101010101. Meaning core # 8,6,4, 2 and 0 would be given to DPDK
                       // core 0 would be used as the DPDK master core by default. To change this, need to 
                       // change DpdkDeviceList::initDpdk() in DpdkDeviceList.cpp and rebuild PcapPlusPlus
#define WORKER_THREAD_CORE 18  // vcpu # (as shown by lstopo). This is the last core on socket #0
#define MTU_LENGTH 1500
#define SEND_RATE_SKIP_PACKETS 318 // helps reduce send rate to 5 Gbps
#define DEFAULT_TTL 12

#define DPDK_PORT 1

std::thread workerThread;
bool stopSending;

void interruptHandler(int s){
    // printf("Caught signal %d\n",s);
    // stop capturing packets
    printf("\nCaught interrupt. Stopping the sending thread...\n");

    
    stopSending = true;

    workerThread.join();    

/*    for(auto& t : workerThreads){
        t.join();
    }*/

}


void send_func(DpdkDevice* dev, pcpp::Packet parsedPacket, bool* stopSending){

    printf("\n[Sending Thread] Starting packet sending ...\n");

    pcpp::QmetadataLayer* qmetadatalayer = parsedPacket.getLayerOfType<pcpp::QmetadataLayer>();

    //int i = 0;
    while(!*stopSending){
      //  if(i == 0){
            dev->sendPacket(parsedPacket,0);
      //  }
      //  i = (i+1) % SEND_RATE_SKIP_PACKETS;
    }

    printf("\n[Sending Thread] Stopping packet sending ...\n");
}


int main(int argv, char* argc[]){

    
    // LoggerPP::getInstance().setAllModlesToLogLevel(LoggerPP::Debug);

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

    int sendPacketsToPort = DPDK_PORT;
    DpdkDevice* sendPacketsTo = DpdkDeviceList::getInstance().getDeviceByPort(sendPacketsToPort);
    if (sendPacketsTo != NULL && !sendPacketsTo->open())
    {
        printf("Could not open port#%d for sending packets\n", sendPacketsToPort);
        exit(1);
    }

    DpdkDevice::LinkStatus linkstatus;
    sendPacketsTo->getLinkStatus(linkstatus);

    printf("The link is %s\n",linkstatus.linkUp?"UP":"Down");

    if(!linkstatus.linkUp){
        printf("Exiting...\n");
        exit(1);
    }
    
/*    // 10 packets sending code 
    for(int i=0; i < 10; i++)
    {
        sendPacketsTo->sendPacket(newPacket, 0); // 0 is the TX queue
    }
    exit(0);
    */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(WORKER_THREAD_CORE, &cpuset); 

    stopSending = false; // this is thread UNSAFE. 
                         // But in our case only the main thread writes. The worker threads simply read.
    
    workerThread = std::thread(send_func, sendPacketsTo, newPacket, &stopSending);
    int aff = pthread_setaffinity_np(workerThread.native_handle(), sizeof(cpu_set_t), &cpuset);
    printf("Sending thread now running on vcpu #%d\n", WORKER_THREAD_CORE);
    
    // code to handle keyboard interrupt
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = interruptHandler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);

    pause();


  
    return 0;
} // end of main()