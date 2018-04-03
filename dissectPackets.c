#include <stdio.h>
#include <stdlib.h>


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
