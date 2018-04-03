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
    int totalPackets = 0, packetSize = 0;
    char packetData[2048], version, ihl, tos, flags, ttl, protocol,
         sourceAddr[16], destAddr[16];
    uint16_t length, id, fragOffset, checksum;
         
    // reads in our number of packets
    fread(&totalPackets, sizeof(int), 1, fp);
    /* prints out how many packets we have
       NOTE: the last formatter is to change packet to singular if needed */
    printf("==== File %s contains %d packet%s\n", 
        file, numPackets, (numPackets == 1) ? "." : "s.");

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
        
        // parses our version (first nibble of first byte)
        version = packetData[0] >> 4;
        /* for this we need to mask off the first nibble (want only second one)
           which is why we bitwise & with 15 (0b00001111) */
        ihl = packetData[0] & 15;
        // parses the type of service
        tos = packetData[1];
        // vv gonna be honest I have NO clue what the fuck this info comes from
        flags = 0; // buf[6] >> 5;
        // parses the time to live
        ttl = packetData[8];
        // parses the protocol
        protocol = packetData[9];
        
        printf("Version:\t\t"               "0x%x (%u)\n"
               "IHL (Header length):\t\t"   "0x%x (%u)\n"
               "Type of service (TOS):\t\t" "0x%x (%u)\n"
               "Total length:\t\t"          "\n"
               "Identification:\t\t"        "\n"
               "IP Flags:\t\t"              "0x%x (%u)\n"
               "Fragment offset:\t\t"       "\n"
               "Time to live (TTL):\t\t"    "0x%x (%u)\n"
               "Protocol:\t\t"              "0x%x (%u)\n"
               "Header checksum:\t\t"       "\n"
               "Source address:\t\t"        "\n"
               "Destination address:\t\t"   "\n",
               version, version, 
               ihl, ihl,
               tos, tos,
               id, id,
               flags, flags,
               ttl, ttl,
               protocol, protocol);
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
