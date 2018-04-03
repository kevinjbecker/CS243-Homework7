///
/// File: dissectPackets.c
///
/// Description: Dissects a binary packet file and prints data about the packets
///              contained in the file.
///              Usage: dissectPackets filename
///
/// @author kjb2503 : Kevin Becker
///
// // // // // // // // // // // // // // // // // // // // // // // // // // //

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define DISSECT_FAILURE -1
#define DISSECT_SUCCESS 0

// an enum used to determine the protocol used in getProtocolName
enum Protocol{
    ICMP=1, IGMP=2, TCP=6, IGRP=9, 
    UDP=17, GRE=47, ESP=50, AH=51, 
    SKIP=57, EIGRP=88, OSPF=89, L2TP=115
};
///
/// Function: getProtocolName
///
/// Description: Returns a string with the initials of a protocol name based
///              upon its value.  USES Protocol enum to determine name.
///
/// @param protocol  The unsigned char which is the protocol number.
///
/// @return A string representing the protocol name.
///
static char* getProtocolName(unsigned char protocol)
{
    switch(protocol)
    {
        case ICMP: return "ICMP";
        case IGMP: return "IGMP";
        case TCP: return "TCP";
        case IGRP: return "IGRP";
        case UDP: return "UDP";
        case GRE: return "GRE";
        case ESP: return "ESP";
        case AH: return "AH";
        case SKIP: return "SKIP";
        case EIGRP: return "EIGRP";
        case OSPF: return "OSPF";
        case L2TP: return "L2TP";
        default: return "Unknown protocol";
    }
}


///
/// Function: combineTwoBytes
///
/// Description: Combines two bytes in network order and returns them in host
///              order as a short.
///
/// @param byte1  The first byte to combine.
/// @param byte2  The second byte to combine.
///
/// @return The two bytes as a short in host order converted from network order.
///
static uint16_t combineTwoBytes(char byte1, char byte2)
{
    /* 
       returns the short representation of the two bytes
       they are passed to the arpa function ntohs by taking the second byte, 
       casting it as a uint16_t, shifting it 8 bits to the left and then ORing
       that result with byte1
       this creates a short out of byte2, shifts it left by 8 bits and appends
       byte1 to the last 8 bits of the new short
       
       bytes must be in this order; function will not work otherwise 
    */
    return ntohs(((uint16_t)byte2 << 8) | byte1);
}


///
/// Function: dissect
///
/// Description: Dissects the packet file and prints data about each packet.
///
/// @param const *file  The name of the file.
/// @param *fp  The FILE pointer to the file which should be read from.
///
/// @return An integer based upon the result of the dissection process.
///         DISSECT_FAILURE if there was any issue encountered with the file;
///         DISSECT_SUCCESS otherwise.
///
static int dissect(const char *file, FILE *fp)
{
    // all of the data we will be extracting will go into these items
    int totalPackets, packetSize;
    // the 8 bit data items
    unsigned char packetData[2048], version = 0, ihl = 0, tos = 0, flags = 0, 
                  ttl = 0, protocol = 0;
    // the 16 bit data items
    uint16_t length = 0, id = 0, fragOffset = 0, checksum = 0;
         
    /* reads in our number of packets
       this includes a check to make sure the file is formatted properly so
       if fread returns something other than 1 (we are reading in 1 integer)
       we might have an issue */
    if(fread(&totalPackets, sizeof(int), 1, fp) != 1)
    {
        /* if we are at the end of the file, we have 0 packets, we are still 
           safe to proceed */
        if(feof(fp))
            totalPackets = 0;
        // otherwise we must exit and return DISSECT_FAILURE
        else
            return DISSECT_FAILURE;
    }
    
    /* prints out how many packets we have
       NOTE: the last formatter is to change packet to singular if needed */
    printf("==== File %s contains %d packet%s\n", 
        file, totalPackets, (totalPackets == 1) ? "." : "s.");

    // defines a buffer of 2048 characters used to hold the data
    for(int packet = 1; packet <= totalPackets; ++packet)
    {
        // prints out what packet we are dissecting
        printf("==> Packet %d\n", packet);
        
        /* reads in our packet size, if it fails we need to stop as something
           is wrong */
        if(fread(&packetSize, sizeof(int), 1, fp) != 1)
            return DISSECT_FAILURE;
            
        // reads in  an area of size packetSize from fp to data
        if(fread(packetData, packetSize, 1, fp) != 1)
            return DISSECT_FAILURE;

        // parses our version (the first nibble of first byte)
        version = packetData[0] >> 4;
        /* for this we need to mask off the first nibble (want only second one)
           which is why we bitwise & with 15 */
        ihl = packetData[0] & 15;
        // parses the type of service
        tos = packetData[1];
        // parses the length
        length = combineTwoBytes(packetData[2], packetData[3]);
        // parses the identification
        id = combineTwoBytes(packetData[4], packetData[5]);
        /* we want to MASK off the last 5 bits rather than shift the bits in 
           order to get the proper print */
        flags = packetData[6] & 224;
        /* for the fragment offset we need to mask off the first three bits
           thus we pass combineTwoBits buf[6] & 31 (binary: 0b00011111) */
        fragOffset = combineTwoBytes((packetData[6] & 31), packetData[7]);
        // parses the time to live
        ttl = packetData[8];
        // parses the protocol
        protocol = packetData[9];
        // parses the checksum
        checksum = combineTwoBytes(packetData[10], packetData[11]);
        
        // prints the parsed data about the packet
        printf("Version:\t\t"               "0x%x (%u)\n"
               "IHL (Header length):\t\t"   "0x%x (%u)\n"
               "Type of service (TOS):\t\t" "0x%x (%u)\n"
               "Total length:\t\t"          "0x%x (%u)\n"
               "Identification:\t\t"        "0x%x (%u)\n"
               "IP Flags:\t\t"              "0x%x (%u)\n"
               "Fragment offset:\t\t"       "0x%x (%u)\n"
               "Time to live (TTL):\t\t"    "0x%x (%u)\n"
               "Protocol:\t\t"              "%s 0x%x (%u)\n"
               "Header checksum:\t\t"       "0x%x (%u)\n"
               "Source address:\t\t"        "%u.%u.%u.%u\n"
               "Destination address:\t\t"   "%u.%u.%u.%u\n",
               version, version, 
               ihl, ihl,
               tos, tos,
               length, length,
               id, id,
               flags, flags,
               fragOffset, fragOffset,
               ttl, ttl,
               getProtocolName(protocol), protocol, protocol,
               checksum, checksum,
               packetData[12], packetData[13], packetData[14], packetData[15],
               packetData[16], packetData[17], packetData[18], packetData[19]);	
        /* we don't need to reset data because we're always reading and parsing
           the first 20 bytes (always constant size, the extra doesn't matter */
    }
    // return 0 upon success
    return DISSECT_SUCCESS;
}


///
/// Function: main
///
/// Description: Runs an instance of dissectPackets
///
/// @param argc  The number of arguments used to run the program.
/// @param **argv  A character array of strings which contains the arguments.
///
int main(int argc, char **argv)
{
    // if we weren't given a specified file we need to print usage message.
    if(argc != 2)
    {
        fprintf(stderr, "Usage: %s filename\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    // if we get here we can proceed with attempting to open the file
    FILE *fp = fopen(argv[1], "rb");

    // function to process packet file
    if(fp == NULL)
    {
        perror("Error opening file");
        return EXIT_FAILURE;
    }

    // dissects the packet file and prints an error message if one encountered
    if(dissect(argv[1], fp) != DISSECT_SUCCESS)
    {
        fprintf(stderr, "An error was encountered while reading the file.\n");
        // closes the file here too just so we don't have any leaks
        fclose(fp);
        return EXIT_FAILURE;
    }

    // closes the packet file after we've processed it
    fclose(fp);

    // return EXIT_SUCCESS as we are at the end and everything worked properly
    return EXIT_SUCCESS;
}

