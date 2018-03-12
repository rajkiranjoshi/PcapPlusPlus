include /usr/local/etc/PcapPlusPlus.mk

all:
	g++ $(PCAPPP_INCLUDES) -o main.o -c main.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o qmetadatarecv main.o $(PCAPPP_LIBS)

clean:
	rm main.o qmetadatarecv
