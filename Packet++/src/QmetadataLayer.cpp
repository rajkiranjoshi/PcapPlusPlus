#define LOG_MODULE PacketLogModuleQmetadataLayer

#include "QmetadataLayer.h"
#include "PayloadLayer.h"
#include "IpUtils.h"
#include "Logger.h"
#include <string.h>
#include <sstream>
#include <endian.h>

namespace pcpp
{

QmetadataLayer::QmetadataLayer(uint16_t flowId)
{
	m_DataLen = sizeof(qmetadatahdr);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	qmetadatahdr* qmetaHdr = (qmetadatahdr*)m_Data;
	qmetaHdr->flowId = htons(flowId);
	m_Protocol = QMETADATA; // important for layer identification for partial parsing
}

uint16_t QmetadataLayer::getFlowId()
{
	qmetadatahdr* qmetaHdr = (qmetadatahdr*)m_Data;
	return ntohs(qmetaHdr->flowId);
}

uint32_t QmetadataLayer::getEnqTimestamp()
{
	qmetadatahdr* qmetaHdr = (qmetadatahdr*)m_Data;
	return ntohl(qmetaHdr->enqTimestamp);
}

uint64_t QmetadataLayer::getGlobalEgressTimestamp()
{
	qmetadatahdr* qmetaHdr = (qmetadatahdr*)m_Data;
	return be64toh(qmetaHdr->globalEgressTimestamp);
}

uint16_t QmetadataLayer::getMarkBit()
{
	qmetadatahdr* qmetaHdr = (qmetadatahdr*)m_Data;
	return ntohs(qmetaHdr->markBit);
}

uint32_t QmetadataLayer::getEnqQdepth()
{
	qmetadatahdr* qmetaHdr = (qmetadatahdr*)m_Data;
	return ntohl(qmetaHdr->enqQdepth);
}

uint32_t QmetadataLayer::getDeqQdepth()
{
	qmetadatahdr* qmetaHdr = (qmetadatahdr*)m_Data;
	return ntohl(qmetaHdr->deqQdepth);
}

uint32_t QmetadataLayer::getDeqTimedelta()
{
	qmetadatahdr* qmetaHdr = (qmetadatahdr*)m_Data;
	return ntohl(qmetaHdr->deqTimedelta);
}


void QmetadataLayer::parseNextLayer()
{
	if (m_DataLen <= sizeof(qmetadatahdr))
		return;

	m_NextLayer = new PayloadLayer(m_Data + sizeof(qmetadatahdr), m_DataLen - sizeof(qmetadatahdr), this, m_Packet);
}



std::string QmetadataLayer::toString()
{
	qmetadatahdr* qmetaHdr;
	qmetaHdr = getQmetadataHeader();
	
	std::ostringstream flowIdStream;
	flowIdStream << std::to_string(ntohs(qmetaHdr->flowId));

	std::ostringstream enqTSStream;
	enqTSStream << std::to_string(ntohl(qmetaHdr->enqTimestamp));

	std::ostringstream globalEgressTSStream;
	globalEgressTSStream << std::to_string(be64toh(qmetaHdr->globalEgressTimestamp));

	std::ostringstream markbitStream;
	markbitStream << std::to_string(ntohs(qmetaHdr->markBit));

	std::ostringstream enqQdepthStream;
	enqQdepthStream << std::to_string(ntohl(qmetaHdr->enqQdepth));

	std::ostringstream deqQdepthStream;
	deqQdepthStream << std::to_string(ntohl(qmetaHdr->deqQdepth));

	std::ostringstream deqTimeDeltaStream;
	deqTimeDeltaStream << std::to_string(ntohl(qmetaHdr->deqTimedelta));

	return "[QmetadataLayer Layer] Seq_No: " + flowIdStream.str() + " Enq_TS: " + enqTSStream.str() 
								  + " Global_Egress_TS: " + globalEgressTSStream.str()
								  + " Mark_Bit: " + markbitStream.str() + " Enq_Qdepth: " + enqQdepthStream.str()
								  + " Deq_Qdepth: " + deqQdepthStream.str() + " Deq_Timedelta: " + deqTimeDeltaStream.str();
}

} // namespace pcpp
