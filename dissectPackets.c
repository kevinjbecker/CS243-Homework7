#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define IP_FORMAT "%u.%u.%u.%u"


static uint16_t combineTwoBytes(char byte1, char byte2)
{
    return ntohs(((uint16_t)byte2 << 8) | byte1);
}


static int dissect(const char * file, FILE* fp)
{
    // all of the data we will be extracting will go into these items
    int totalPackets = 0, packetSize = 0;
    // the 8 bit data items
    unsigned char packetData[2048], version = 0, ihl = 0, tos = 0, flags = 0, 
                  ttl = 0, protocol = 0, sourceAddr[17], destAddr[17];
    // the 16 bit data items
    uint16_t length = 0, id = 0, fragOffset = 0, checksum = 0;
         
    // reads in our number of packets
    fread(&totalPackets, sizeof(int), 1, fp);
    /* prints out how many packets we have
       NOTE: the last formatter is to change packet to singular if needed */
    printf("==== File %s contains %d packet%s\n", 
        file, totalPackets, (totalPackets == 1) ? "." : "s.");

    // defines a buffer of 2048 characters used to hold the data
    for(int packet = 1; packet <= totalPackets; ++packet)
    {
        // prints out what packet we are dissecting
        printf("==> Packet %d\n", packet);
        fread(&packetSize, sizeof(int), 1, fp);
        //printf("Packet has %d size\n", packetSize);
        /* reads in packet
           reads an area of size packetSize from fp to data */
        fread(packetData, packetSize, 1, fp);
        /* 
           FOR PARSING: 
           Version: bits 0-3
           IHL: 4-7
           TOS: 8-15
           Total Length: 16-31
           Identification: 32-47
           IP Flags: 48-50
           Fragment offset: 51-63
           TTL: 64-71
           Protocol: 72-79
           Header checksum: 80-95
           Source address: 96-131
           Destination address: 132-163
        */    
        
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

        sprintf(sourceAddr, IP_FORMAT, packetData[12], packetData[13], 
                packetData[14], packetData[15]);
        sprintf(destAddr, IP_FORMAT, packetData[16], packetData[17], 
                packetData[18], packetData[19]);
        
        printf("Version:\t\t"               "0x%x (%u)\n"
               "IHL (Header length):\t\t"   "0x%x (%u)\n"
               "Type of service (TOS):\t\t" "0x%x (%u)\n"
               "Total length:\t\t"          "0x%x (%u)\n"
               "Identification:\t\t"        "0x%x (%u)\n"
               "IP Flags:\t\t"              "0x%x (%u)\n"
               "Fragment offset:\t\t"       "0x%x (%u)\n"
               "Time to live (TTL):\t\t"    "0x%x (%u)\n"
               "Protocol:\t\t"              "0x%x (%u)\n"
               "Header checksum:\t\t"       "0x%x (%u)\n"
               "Source address:\t\t"        "%s\n"
               "Destination address:\t\t"   "%s\n",
               version, version, 
               ihl, ihl,
               tos, tos,
               length, length,
               id, id,
               flags, flags,
               fragOffset, fragOffset,
               ttl, ttl,
               protocol, protocol,
               checksum, checksum,
               sourceAddr,
               destAddr);
         break;
        /* we don't need to reset data because we're always reading and parsing
           the first 20 bytes (always constant size, the "extra isn't useful */
    }

    return 0;
}


int main(int argc, char **argv)
{
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

    // processes the packet file
    if( dissect(argv[1], fp) != 0 )
    {
        fprintf(stderr, "There was an error reading your file.\n");
        // closes the file here too just so we don't have any leaks
        fclose(fp);
        return EXIT_FAILURE;
    }

    // closes the packet file after we've processed it
    fclose(fp);

    return EXIT_SUCCESS;
}
