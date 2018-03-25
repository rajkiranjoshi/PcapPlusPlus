#include "stdlib.h"
#include "PcapFileDevice.h"
#include "PlatformSpecificUtils.h"
#include "PcapPlusPlusVersion.h"
#include "SystemUtils.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "Packet.h"
#include "UdpLayer.h"
#include "PayloadLayer.h"
#include "QmetadataLayer.h"
#include <arpa/inet.h>
#include <iostream>
#include <signal.h>
#include <string.h>
#include <sstream>
#include <getopt.h>
#include <algorithm> // for std::find
#include <iterator> // for std::begin, std::end
#include <unordered_map>

#define NUM_FIELDS 9

typedef struct
{
    struct timeval captureTstamp;
    int frameLen;
    uint16_t flowId;
    uint32_t enqTimestamp;
    uint64_t globalEgressTimestamp;
    uint16_t markBit;
    uint32_t enqQdepth;
    uint32_t deqQdepth;
    uint32_t deqTimedelta;
} ExtractedPacket;

/*static struct option ParseOptions[] =
{
    {"field_list", required_argument, 0, 'f'},
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'v'},
    {0, 0, 0, 0}
};
*/
static std::string valid_fields[NUM_FIELDS] = {"capturetstamp", "framelen", "egressglobaltstamp", "flowid", "enqtstamp", "markbit", 
                                     "enqqdepth", "deqqdepth", "deqtimedelta"};



void printPacket(const ExtractedPacket &pkt, const std::vector<std::string> &currFieldsVectors, const unsigned long int &base_usecs)
{
        std::unordered_map<std::string,std::string> stringValueMap;
        stringValueMap.clear();

        unsigned long int curr_usecs = pkt.captureTstamp.tv_sec * 1000000L + pkt.captureTstamp.tv_usec;
        unsigned long int actual_usecs = curr_usecs - base_usecs;

        unsigned long int sec = actual_usecs / 1000000L;
        unsigned long int usec = actual_usecs % 1000000L;     
        
        std::string captureTsString = "";
        captureTsString = captureTsString + std::to_string(sec) + "." + std::to_string(usec);
        
        stringValueMap["capturetstamp"] = captureTsString;
        stringValueMap["framelen"] = std::to_string(pkt.frameLen);
        stringValueMap["flowid"] = std::to_string(pkt.flowId);
        stringValueMap["enqtstamp"] = std::to_string(pkt.enqTimestamp);
        stringValueMap["egressglobaltstamp"] = std::to_string(pkt.globalEgressTimestamp);
        stringValueMap["markbit"] = std::to_string(pkt.markBit);
        stringValueMap["enqqdepth"] = std::to_string(pkt.enqQdepth);
        stringValueMap["deqqdepth"] = std::to_string(pkt.deqQdepth);
        stringValueMap["deqtimedelta"] = std::to_string(pkt.deqTimedelta);

        std::string outputString = "";

        for(std::vector<std::string>::const_iterator it = currFieldsVectors.begin(); it != currFieldsVectors.end(); ++it)
        {
            outputString = outputString + stringValueMap[*it];
            outputString = outputString + " ";
        }

        outputString.pop_back(); // remove the extra space at the end

        std::cout << outputString << "\n";
}



/**
 * Print application usage
 */
void printUsage(FILE *fout) {
    fprintf(fout, "\nUsage:\n"
            "------\n"
            "%s [-hv] [-f field_list] pcapfilename\n"
            "\nOptions:\n\n"
            "    -f field_list   : The list of fields in sequence (comma separated)\n"
            "                      The output will print these fields in sequence, separated by a single space\n"
            "                      List of fields:\n"
            "                      flowid\n"
            "                      enqtstamp (18-bit ns)\n"
            "                      egressglobaltstamp (48-bit ns)\n"
            "                      markbit\n"
            "                      enqqdepth (cells)\n"
            "                      deqqdepth (cells)\n"
            "                      deqtimedelta\n"
            "                      framelen (bytes)\n"
            "                      capturetstamp (s.us)\n"
            "    -r              : Reduced file - only extract pkts when qdepths have changed"
            "    -h              : Displays this help message and exits\n"
            "    -v              : Displays the current version and exits\n", pcpp::AppName::get().c_str());
            
}


/**
 * Print application version
 */
void printAppVersion()
{
    printf("%s %s\n", pcpp::AppName::get().c_str(), pcpp::getPcapPlusPlusVersionFull().c_str());
    printf("Built: %s\n", pcpp::getBuildDateTime().c_str());
    printf("Built from: %s\n", pcpp::getGitInfo().c_str());
    exit(0);
}

bool validate_fields(std::vector<std::string> flist){
    bool result = true;
    for(int i=0; i < flist.size(); i++){
        bool tmp = std::find(std::begin(valid_fields), std::end(valid_fields), flist[i]) != std::end(valid_fields);
        if(tmp == false){
            fprintf(stderr, "Invalid field '%s'\n", flist[i].c_str());
            result = false;
            break;
        }
    }
    return result;
}


int main(int argc, char* argv[]){

    pcpp::AppName::init(argc, argv);

    std::string field_list = "", filename = "";

    bool fieldlistProvided = false;
    bool reducedFile = false;
    int optionIndex = 0;
    char opt = 0;

    while((opt = getopt(argc, argv, "f:rhv")) != -1) //, ParseOptions, &optionIndex)) != -1)
    {
        switch (opt)
        {
            case 'f':
                field_list = optarg;
                fieldlistProvided = true;
                break;
            case 'r':
                reducedFile = true;
                break;
            case 'h':
                printUsage(stdout);
                exit(0);
                break;
            case 'v':
                printAppVersion();
                exit(0);
                break;
            default:
                fprintf(stderr, "Something went wrong in options parsing\n");
                printUsage(stderr);
                exit(1);
        }
    }

    if (argv[optind] == NULL) {
        fprintf(stderr, "The pcapfilename is a mandatory argument\n");
        printUsage(stderr);
        exit(1);
    }
    else
        filename = argv[optind];

    // printf("%s\n%s\n",field_list.c_str(),filename.c_str());
    

    
    std::vector<std::string> fieldsVector;

    if(fieldlistProvided){
        
        std::stringstream ss(field_list);

        while(ss.good()){
            std::string substr;
            getline(ss,substr,',');
            fieldsVector.push_back(substr);
        }

        if(!validate_fields(fieldsVector)){
            printUsage(stderr);
            exit(1);
        }
    }


    // use the IFileReaderDevice interface to automatically identify file type (pcap/pcap-ng)
    // and create an interface instance that both readers implement
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(filename.c_str());

    // verify that a reader interface was indeed created
    if (reader == NULL)
    {
        fprintf(stderr, "Cannot determine reader for file type\n");
        exit(1);
    }

    // open the reader for reading
    if (!reader->open())
    {
        fprintf(stderr, "Cannot open %s for reading\n",filename.c_str());
        exit(1);
    }

    // the packet container
    pcpp::RawPacket rawPacket;
    
    std::vector<std::string> currFieldsVector;

        if(fieldlistProvided){
            currFieldsVector = fieldsVector;
        }
        else{
            currFieldsVector.assign(valid_fields, valid_fields + NUM_FIELDS); // copy valid_fields array into currFieldsVector
        }

    bool isFirstPacket = true;
    // unsigned long int base_sec;
    unsigned long int base_usecs;
    uint64_t prevWrittenTimestamp;

    // Print the column header
    std::string outputString = "";
    for(std::vector<std::string>::iterator it = currFieldsVector.begin(); it != currFieldsVector.end(); ++it)
    {
        outputString = outputString + *it;
        outputString = outputString + " ";
    }
    outputString.pop_back(); // remove the extra space at the end
    std::cout << outputString << "\n";

    ExtractedPacket currPkt, prevPkt;

    while (reader->getNextPacket(rawPacket))
    {
        // parse the raw packet
        pcpp::Packet parsedPacket(&rawPacket, pcpp::QMETADATA); // QMETADATA -> parse until this layer only                                                
        pcpp::QmetadataLayer* qmlayer = parsedPacket.getLayerOfType<pcpp::QmetadataLayer>();

        // Extract the outside parameters: capturetstamp, framelen
        currPkt.captureTstamp = rawPacket.getPacketTimeStamp();
        currPkt.frameLen = rawPacket.getFrameLength();

        // Extract the qmetadata parameters
        currPkt.flowId = qmlayer->getFlowId();
        currPkt.enqTimestamp = qmlayer->getEnqTimestamp();
        currPkt.globalEgressTimestamp = qmlayer->getGlobalEgressTimestamp();
        currPkt.markBit = qmlayer->getMarkBit();
        currPkt.enqQdepth = qmlayer->getEnqQdepth();
        currPkt.deqQdepth = qmlayer->getDeqQdepth();
        currPkt.deqTimedelta = qmlayer->getDeqTimedelta();

        if(isFirstPacket){
            base_usecs  = currPkt.captureTstamp.tv_sec * 1000000L + currPkt.captureTstamp.tv_usec;
            printPacket(currPkt, currFieldsVector, base_usecs);
            isFirstPacket = false;

            if(reducedFile){
                prevPkt = currPkt;
                prevWrittenTimestamp = currPkt.globalEgressTimestamp;
            }

            continue;
        }

        if(reducedFile){
            if(currPkt.deqQdepth != prevPkt.deqQdepth || currPkt.enqQdepth != prevPkt.enqQdepth){
                // something has changed in the queue
                if(prevPkt.globalEgressTimestamp != prevWrittenTimestamp){
                    // we need to write the previous packet
                    printPacket(prevPkt, currFieldsVector, base_usecs);
                }
                printPacket(currPkt, currFieldsVector, base_usecs);
                prevWrittenTimestamp = currPkt.globalEgressTimestamp;
            }
            prevPkt = currPkt;
        }
        else{// just print the current packet
            printPacket(currPkt, currFieldsVector, base_usecs);
        }
    } // end of the while loop

    if(reducedFile){
        // write the last pkt in case it was not already written
        if(prevPkt.globalEgressTimestamp != prevWrittenTimestamp){
            printPacket(prevPkt, currFieldsVector, base_usecs);
        }
    }

    reader->close();

    return 0;
} // end of main()
