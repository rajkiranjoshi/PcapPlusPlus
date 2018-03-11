#include "stdlib.h"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include "PlatformSpecificUtils.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "PayloadLayer.h"
#include "QmetadataLayer.h"

#define PAYLOAD_LENGTH 1438
#define DEFAULT_TTL 12  


int main(int argv, char* argc[]){

    // construct the required packet
    pcpp::Packet newPacket(1500);
    pcpp::MacAddress srcMac("3c:fd:fe:b7:e7:f4");
    pcpp::MacAddress dstMac("aa:aa:aa:aa:aa:aa");
    pcpp::IPv4Address srcIP(std::string("10.1.1.2"));
    pcpp::IPv4Address dstIP(std::string("30.1.1.2"));
    uint16_t srcPort = 1; // 37777;
    uint16_t dstPort = 7777;

    pcpp::EthLayer newEthLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP); // 0x0800 -> IPv4
    pcpp::IPv4Layer newIPv4Layer(srcIP, dstIP);
    newIPv4Layer.getIPv4Header()->timeToLive = DEFAULT_TTL;
    pcpp::UdpLayer newUDPLayer(srcPort, dstPort);
    pcpp::QmetadataLayer newQmetadataLayer(false);

    newQmetadataLayer.getQmetadataHeader()->seqNo=1;
    newQmetadataLayer.getQmetadataHeader()->markBit=1;
    
    uint8_t payload[PAYLOAD_LENGTH];
    int datalen = 4;
    char data[datalen] = {'D','A','T','A'};
    // Put the data values into the payload
    int j = 0;
    for(int i=0; i < PAYLOAD_LENGTH; i++){
        payload[i] = (uint8_t) int(data[j]);
        j = (j + 1) % datalen;
    }

    // construct the payload layer
    pcpp::PayloadLayer newPayLoadLayer(payload, PAYLOAD_LENGTH, false);

    newPacket.addLayer(&newEthLayer);
    newPacket.addLayer(&newIPv4Layer);
    newPacket.addLayer(&newUDPLayer);
    newPacket.addLayer(&newQmetadataLayer);
    newPacket.addLayer(&newPayLoadLayer);

    // compute the calculated fields
    newUDPLayer.computeCalculateFields();
    newUDPLayer.calculateChecksum(true);
    newIPv4Layer.computeCalculateFields(); // this takes care of the IPv4 checksum


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

/*
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

    return 0;
} // end of main()
