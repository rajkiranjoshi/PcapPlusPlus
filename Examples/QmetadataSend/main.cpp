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

#define MTU_LENGTH 1500
#define DEFAULT_TTL 12  


int main(int argv, char* argc[]){

    // construct the required packet
    pcpp::Packet newPacket(MTU_LENGTH);
    pcpp::MacAddress srcMac("3c:fd:fe:b7:e7:f4");
    pcpp::MacAddress dstMac("aa:aa:aa:aa:aa:aa");
    pcpp::IPv4Address srcIP(std::string("10.1.1.2"));
    pcpp::IPv4Address dstIP(std::string("20.1.1.2"));
    uint16_t srcPort = 37777;
    uint16_t dstPort = 7777;

    pcpp::EthLayer newEthLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP); // 0x0800 -> IPv4
    pcpp::IPv4Layer newIPv4Layer(srcIP, dstIP);
    newIPv4Layer.getIPv4Header()->timeToLive = DEFAULT_TTL;
    pcpp::UdpLayer newUDPLayer(srcPort, dstPort);
    pcpp::QmetadataLayer newQmetadataLayer(1);

    // newQmetadataLayer.getQmetadataHeader()->enqTimestamp=htonl(1);
    // newQmetadataLayer.getQmetadataHeader()->markBit=htons(1);
    // newQmetadataLayer.getQmetadataHeader()->enqQdepth=htonl(2);
    // newQmetadataLayer.getQmetadataHeader()->deqQdepth=htonl(3);
    // newQmetadataLayer.getQmetadataHeader()->deqTimedelta=htonl(4);

    int length_so_far = newEthLayer.getHeaderLen() + newIPv4Layer.getHeaderLen() + 
                        newUDPLayer.getHeaderLen() + newQmetadataLayer.getHeaderLen();
    int payload_length = MTU_LENGTH - length_so_far;
    
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

/*
    // write the packet to a pcap file
    pcpp::PcapFileWriterDevice pcapWriter("output.pcap", pcpp::LINKTYPE_ETHERNET);
    if (!pcapWriter.open())
    {
        printf("Cannot open output.pcap for writing\n");
        exit(1);
    }

    const pcpp::RawPacket* rawPacket; // non constant pointer to constant data
    rawPacket = newPacket.getRawPacketReadOnly();
    pcapWriter.writePacket(*rawPacket);
    pcapWriter.close();


    pcpp::PcapFileReaderDevice pcapReader("output.pcap");

    if(!pcapReader.open()){
        printf("Cannot open the pcap file for reading\n");
        exit(1);
    }


    // read the first (and only) packet from the file
    pcpp::RawPacket rawPkt;
    if (!pcapReader.getNextPacket(rawPkt))
    {
        printf("Couldn't read the first packet in the file\n");
        return 1;
    }

    // parse the raw packet into a parsed packet
    pcpp::Packet parsedPacket(&rawPkt);

    pcpp::QmetadataLayer* qmlayer = parsedPacket.getLayerOfType<pcpp::QmetadataLayer>();

    std::cout << qmlayer->toString();
*/

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

    for(int i=0; i < 5; i++){
        newQmetadataLayer.setSeqNo(i);
        dev->sendPacket(&newPacket);
    }

    

    return 0;
} // end of main()
