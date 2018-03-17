#define LOG_MODULE PacketLogModuleQmetadataLayer

#include "QmetadataLayer.h"
#include "PayloadLayer.h"
#include "IpUtils.h"
#include "Logger.h"
#include <string.h>
#include <sstream>

namespace pcpp
{

QmetadataLayer::QmetadataLayer(uint32_t seqNo)
{
	m_DataLen = sizeof(qmetadatahdr);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	qmetadatahdr* qmetaHdr = (qmetadatahdr*)m_Data;
	qmetaHdr->seqNo = htonl(seqNo);
	m_Protocol = QMETADATA; // important for layer identification for partial parsing
}

void QmetadataLayer::setSeqNo(uint32_t seqNo){
	qmetadatahdr* qmetaHdr = (qmetadatahdr*)m_Data;
	qmetaHdr->seqNo = htonl(seqNo);
	m_Protocol = QMETADATA; // important for layer identification for partial parsing
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
	
	std::ostringstream seqNoStream;
	seqNoStream << std::to_string(ntohl(qmetaHdr->seqNo));

	std::ostringstream enqTSStream;
	enqTSStream << std::to_string(ntohl(qmetaHdr->enqTimestamp));

	std::ostringstream markbitStream;
	markbitStream << std::to_string(ntohs(qmetaHdr->markBit));

	std::ostringstream enqQdepthStream;
	enqQdepthStream << std::to_string(ntohl(qmetaHdr->enqQdepth));

	std::ostringstream deqQdepthStream;
	deqQdepthStream << std::to_string(ntohl(qmetaHdr->deqQdepth));

	std::ostringstream deqTimeDeltaStream;
	deqTimeDeltaStream << std::to_string(ntohl(qmetaHdr->deqTimedelta));

	return "[QmetadataLayer Layer] Seq No: " + seqNoStream.str() + " Enq TS: " + enqTSStream.str()
								  + " Mark Bit: " + markbitStream.str() + " Enq Qdepth: " + enqQdepthStream.str()
								  + " Deq Qdepth: " + deqQdepthStream.str() + " Deq Timedelta: " + deqTimeDeltaStream.str();
}

} // namespace pcpp
