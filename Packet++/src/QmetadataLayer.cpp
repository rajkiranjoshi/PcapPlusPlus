#define LOG_MODULE PacketLogModuleQmetadataLayer

#include "QmetadataLayer.h"
#include "PayloadLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "Logger.h"
#include <string.h>
#include <sstream>

namespace pcpp
{

QmetadataLayer::QmetadataLayer(bool dummy)
{
	m_DataLen = sizeof(qmetadatahdr);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = QMETADATA;
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
	seqNoStream << std::to_string(qmetaHdr->seqNo);

	std::ostringstream enqTSStream;
	enqTSStream << std::to_string(qmetaHdr->enqTimestamp);

	std::ostringstream markbitStream;
	markbitStream << std::to_string(qmetaHdr->markBit);

	std::ostringstream enqQdepthStream;
	enqQdepthStream << std::to_string(qmetaHdr->enqQdepth);

	std::ostringstream deqQdepthStream;
	deqQdepthStream << std::to_string(qmetaHdr->deqQdepth);

	std::ostringstream deqTimeDeltaStream;
	deqTimeDeltaStream << std::to_string(qmetaHdr->deqTimedelta);

	return "QmetadataLayer Layer, Seq No: " + seqNoStream.str() + ", Enq TS: " + enqTSStream.str()
								  + ", Mark Bit: " + markbitStream.str() + ", Enq Qdepth: " + enqQdepthStream.str()
								  + ", Deq Qdepth: " + deqQdepthStream.str() + ", Deq Timedelta: " + deqTimeDeltaStream.str() + "\n";
}

} // namespace pcpp
