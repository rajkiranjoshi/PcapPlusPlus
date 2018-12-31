include /usr/local/etc/PcapPlusPlus.mk

.PHONY: all clean

all: getpacketdrops getseqnumbers reorderpackets getextrapackets
	

getpacketdrops: getPacketDrops.cpp
	g++ $(PCAPPP_INCLUDES) -std=c++11 -o getPacketDrops.o -c getPacketDrops.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o getpacketdrops getPacketDrops.o $(PCAPPP_LIBS)

getseqnumbers: getSeqNumbers.cpp
	g++ $(PCAPPP_INCLUDES) -std=c++11 -o getSeqNumbers.o -c getSeqNumbers.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o getseqnumbers getSeqNumbers.o $(PCAPPP_LIBS)

gettsseqnumbers: getTsSeqNumbers.cpp
	g++ $(PCAPPP_INCLUDES) -std=c++11 -o getTsSeqNumbers.o -c getTsSeqNumbers.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o gettsseqnumbers getTsSeqNumbers.o $(PCAPPP_LIBS)

getextrapackets: getExtraPackets.cpp
	g++ $(PCAPPP_INCLUDES) -std=c++11 -o getExtraPackets.o -c getExtraPackets.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o getextrapackets getExtraPackets.o $(PCAPPP_LIBS)

reorderpackets: reorderPackets.cpp
	g++ $(PCAPPP_INCLUDES) -std=c++11 -o reorderPackets.o -c reorderPackets.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o reorderpackets reorderPackets.o $(PCAPPP_LIBS)	

getsrcportnumbers: getSrcPortNumbers.cpp
	g++ $(PCAPPP_INCLUDES) -std=c++11 -o getSrcPortNumbers.o -c getSrcPortNumbers.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o getsrcportnumbers getSrcPortNumbers.o $(PCAPPP_LIBS)	

getfct: getFCT.cpp
	g++ $(PCAPPP_INCLUDES) -std=c++11 -o getFCT.o -c getFCT.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o getfct getFCT.o $(PCAPPP_LIBS)	

clean:
	rm *.o getpacketdrops getseqnumbers getextrapackets reorderpackets gettsseqnumbers getsrcportnumbers getfct


