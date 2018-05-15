#define LOG_MODULE PacketLogModuleSnapshotDebugLayer

#include "SnapshotDebugLayer.h"
#include "PayloadLayer.h"
#include "IpUtils.h"
#include "Logger.h"
#include <string.h>
#include <sstream>
#include <endian.h>

namespace pcpp
{

uint64_t SnapshotDebugLayer::getGlobalIngressTimestamp()
{
    uint64_t globalIngressTimestamp;

    snapshotdebughdr* snapshotDebugHdr = (snapshotdebughdr*)m_Data;
    globalIngressTimestamp = ntohs(snapshotDebugHdr->globalIngressTimestamp_hi_16);
    globalIngressTimestamp = globalIngressTimestamp << 32; // left shift by 32 bits
    globalIngressTimestamp = globalIngressTimestamp + ntohl(snapshotDebugHdr->globalIngressTimestamp_lo_32);

    return globalIngressTimestamp;
}

uint64_t SnapshotDebugLayer::getGlobalEgressTimestamp()
{
    uint64_t globalEgressTimestamp;

    snapshotdebughdr* snapshotDebugHdr = (snapshotdebughdr*)m_Data;
    globalEgressTimestamp = ntohs(snapshotDebugHdr->globalIngressTimestamp_hi_16);
    globalEgressTimestamp = globalEgressTimestamp << 32; // left shift by 32 bits
    globalEgressTimestamp = globalEgressTimestamp + ntohl(snapshotDebugHdr->globalEgressTimestamp_lo_32);

    return globalEgressTimestamp;
}

uint32_t SnapshotDebugLayer::getEnqQdepth()
{
    snapshotdebughdr* snapshotDebugHdr = (snapshotdebughdr*)m_Data;
    return ntohl(snapshotDebugHdr->enqQdepth);
}

uint32_t SnapshotDebugLayer::getDeqQdepth()
{
    snapshotdebughdr* snapshotDebugHdr = (snapshotdebughdr*)m_Data;
    return ntohl(snapshotDebugHdr->deqQdepth);
}


uint64_t SnapshotDebugLayer::getOrigEgressGlobalTimestamp(){
    snapshotdebughdr* snapshotDebugHdr = (snapshotdebughdr*)m_Data;
    return be64toh(snapshotDebugHdr->origEgressGlobalTimestamp);
}


uint64_t SnapshotDebugLayer::getNewEgressGlobalTimestamp(){
    snapshotdebughdr* snapshotDebugHdr = (snapshotdebughdr*)m_Data;
    return be64toh(snapshotDebugHdr->newEgressGlobalTimestamp);
}

uint32_t SnapshotDebugLayer::getNewEnqTimestamp(){
    snapshotdebughdr* snapshotDebugHdr = (snapshotdebughdr*)m_Data;
    return ntohl(snapshotDebugHdr->newEnqTimestamp);
}


void SnapshotDebugLayer::parseNextLayer()
{
    if (m_DataLen <= sizeof(snapshotdebughdr))
        return;

    m_NextLayer = new PayloadLayer(m_Data + sizeof(snapshotdebughdr), m_DataLen - sizeof(snapshotdebughdr), this, m_Packet);
}



std::string SnapshotDebugLayer::toString()
{

    std::ostringstream globalIngressTSStream;
    globalIngressTSStream << std::to_string(getGlobalIngressTimestamp()); 

    std::ostringstream globalEgressTSStream;
    globalEgressTSStream << std::to_string(getGlobalEgressTimestamp());

    std::ostringstream enqQdepthStream;
    enqQdepthStream << std::to_string(getEnqQdepth());

    std::ostringstream deqQdepthStream;
    deqQdepthStream << std::to_string(getDeqQdepth());


    return "toString not functional!!";
    /*return "[SnapshotLayer Layer] Global_Ingress_TS: " + globalIngressTSStream.str()
                                  + " Global_Egress_TS: " + globalEgressTSStream.str()
                                  + " Enq_Qdepth: " + enqQdepthStream.str()
                                  + " Deq_Qdepth: " + deqQdepthStream.str();*/
}

} // namespace pcpp
