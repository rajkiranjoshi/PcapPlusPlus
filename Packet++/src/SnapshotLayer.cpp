#define LOG_MODULE PacketLogModuleSnapshotLayer

#include "SnapshotLayer.h"
#include "PayloadLayer.h"
#include "IpUtils.h"
#include "Logger.h"
#include <string.h>
#include <sstream>
#include <endian.h>

namespace pcpp
{

uint64_t SnapshotLayer::getGlobalIngressTimestamp()
{
    uint64_t globalIngressTimestamp;

    snapshothdr* snapshotHdr = (snapshothdr*)m_Data;
    globalIngressTimestamp = ntohs(snapshotHdr->globalIngressTimestamp_hi_16);
    globalIngressTimestamp = globalIngressTimestamp << 32; // left shift by 32 bits
    globalIngressTimestamp = globalIngressTimestamp + ntohl(snapshotHdr->globalIngressTimestamp_lo_32);

    return globalIngressTimestamp;
}

uint64_t SnapshotLayer::getGlobalEgressTimestamp()
{
    uint64_t globalEgressTimestamp;

    snapshothdr* snapshotHdr = (snapshothdr*)m_Data;
    globalEgressTimestamp = ntohs(snapshotHdr->globalIngressTimestamp_hi_16);
    globalEgressTimestamp = globalEgressTimestamp << 32; // left shift by 32 bits
    globalEgressTimestamp = globalEgressTimestamp + ntohl(snapshotHdr->globalEgressTimestamp_lo_32);

    return globalEgressTimestamp;
}

uint32_t SnapshotLayer::getEnqQdepth()
{
    snapshothdr* snapshotHdr = (snapshothdr*)m_Data;
    return ntohl(snapshotHdr->enqQdepth);
}

uint32_t SnapshotLayer::getDeqQdepth()
{
    snapshothdr* snapshotHdr = (snapshothdr*)m_Data;
    return ntohl(snapshotHdr->deqQdepth);
}



void SnapshotLayer::parseNextLayer()
{
    if (m_DataLen <= sizeof(snapshothdr))
        return;

    m_NextLayer = new PayloadLayer(m_Data + sizeof(snapshothdr), m_DataLen - sizeof(snapshothdr), this, m_Packet);
}



std::string SnapshotLayer::toString()
{

    std::ostringstream globalIngressTSStream;
    globalIngressTSStream << std::to_string(getGlobalIngressTimestamp()); 

    std::ostringstream globalEgressTSStream;
    globalEgressTSStream << std::to_string(getGlobalEgressTimestamp());

    std::ostringstream enqQdepthStream;
    enqQdepthStream << std::to_string(getEnqQdepth());

    std::ostringstream deqQdepthStream;
    deqQdepthStream << std::to_string(getDeqQdepth());


    return "[SnapshotLayer Layer] Global_Ingress_TS: " + globalIngressTSStream.str()
                                  + " Global_Egress_TS: " + globalEgressTSStream.str()
                                  + " Enq_Qdepth: " + enqQdepthStream.str()
                                  + " Deq_Qdepth: " + deqQdepthStream.str();
}

} // namespace pcpp
