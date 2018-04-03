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
    int numPackets = 0, packetSize = 0;
    char packetData[2048];
         
    // reads in our number of packets
    fread(&numPackets, sizeof(int), 1, fp);
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
