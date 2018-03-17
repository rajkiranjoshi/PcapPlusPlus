include /usr/local/etc/PcapPlusPlus.mk

all:
	g++ $(PCAPPP_INCLUDES) -std=c++11 -o main.o -c main.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o qmetadatasend main.o $(PCAPPP_LIBS)

clean:
	rm main.o
	rm qmetadatasend