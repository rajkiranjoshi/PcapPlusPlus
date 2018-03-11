#ifndef PACKETPP_QMETADATA_LAYER
#define PACKETPP_QMETADATA_LAYER

#include "Layer.h"
#include <vector>
#include <map>
#if defined(WIN32) || defined(WINx64)
#include <winsock2.h>
#elif LINUX
#include <in.h>
#endif

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @struct qmetadata
	 * Represents the fixed queuing metadata header
	 */
#pragma pack(push, 1)
	struct qmetadatahdr
	{
		/** Flow's pkt sequence number */
		uint32_t seqNo;
		/** Enqueue Timestamp */
		uint32_t enqTimestamp;

#if (BYTE_ORDER == LITTLE_ENDIAN)
		uint64_t
		/**	To mark candidate snapshot pkts */
			markBit:1,
		/** Extra padding bits */
			_pad0:12,
		/**	Enqueue Queue Depth */
			enqQdepth:19,
		/**	Extra padding bits */
			_pad1:13,
		/** Dequeue Queue Depth */
			deqQdepth:19;
#endif
		/** Dequeue Timedelta */
		uint32_t deqTimedelta;
	};
#pragma pack(pop)


	/**
	 * @class QmetadataLayer
	 * Represents the Qmetadata protocol layer.<BR>
	 */
	class QmetadataLayer : public Layer
	{
		
	public:

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		QmetadataLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = QMETADATA; }

		/**
		 * A constructor that creates an empty Qmetadata layer: all fields are set to zero
		 */
		QmetadataLayer(bool dummy); // workaround for C++11 default constructor stuff
			
		/**
		 * Get a pointer to the Qmetadata header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref qmetadatahdr
		 */
		inline qmetadatahdr* getQmetadataHeader() { return (qmetadatahdr*)m_Data; }


		// implement abstract methods

		/**
		 * Currently identifies the following next layer: PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of @ref qmetadatahdr
		 */
		inline size_t getHeaderLen() { return sizeof(qmetadatahdr); }

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields() {}

		std::string toString();

		OsiModelLayer getOsiModelLayer() { return OsiModelApplicationLayer; }

	};

} // namespace pcpp

#endif /* PACKETPP_QMETADATA_LAYER */
