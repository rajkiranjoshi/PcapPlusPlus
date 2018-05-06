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

uint64_t QmetadataLayer::getGlobalIngressTimestamp()
{
	qmetadatahdr* qmetaHdr = (qmetadatahdr*)m_Data;
	return be64toh(qmetaHdr->globalIngressTimestamp);
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

	std::ostringstream globalIngressTSStream;
	globalIngressTSStream << std::to_string(be64toh(qmetaHdr->globalIngressTimestamp));	

	std::ostringstream globalEgressTSStream;
	globalEgressTSStream << std::to_string(be64toh(qmetaHdr->globalEgressTimestamp));

	std::ostringstream markbitStream;
	markbitStream << std::to_string(ntohs(qmetaHdr->markBit));

	std::ostringstream enqQdepthStream;
	enqQdepthStream << std::to_string(ntohl(qmetaHdr->enqQdepth));

	std::ostringstream deqQdepthStream;
	deqQdepthStream << std::to_string(ntohl(qmetaHdr->deqQdepth));


	return "[QmetadataLayer Layer] Seq_No: " + flowIdStream.str()
								  + " Global_Ingress_TS: " + globalIngressTSStream.str()
								  + " Global_Egress_TS: " + globalEgressTSStream.str()
								  + " Mark_Bit: " + markbitStream.str() + " Enq_Qdepth: " + enqQdepthStream.str()
								  + " Deq_Qdepth: " + deqQdepthStream.str() ;
}

} // namespace pcpp
