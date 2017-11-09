// TEST CASE FOR MAGIC NUMBER
// This program is test case for Magic Number such that it will test the magic numbers of all blocks in block chain

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include "format.h"
#include "parse.h"

#include <stdlib.h>
#include <string.h>
enum parse_blk_state p_blk_s = P_BLK_MAGIC;

// enumerating the magic number

enum magic_net parse_is_magic(uint32_t m)
{
	enum magic_net mn = MAGIC_NET_NONE;
	if (m == MAGIC_MAIN) {
        mn = MAGIC_NET_MAIN;
    } else if (m == MAGIC_TESTNET) {
        mn = MAGIC_NET_TESTNET;
    } else if (m == MAGIC_TESTNET3) {
        mn = MAGIC_NET_TESTNET3;
    } else if (m == MAGIC_NAMECOIN) {
        mn = MAGIC_NET_NAMECOIN;
    }
    return mn;
}

// testing the magic number. Here we are checking the magic number of each block
// Magic number obtained after parsing is Actual Magic Number
// It is compared asgainst actual magic number of Litecoin ( 0xDBB6C0FB)

int testmagicnum(struct block *b)
{
    int flag=0;
    uint8_t i;
    uint32_t expectedmagic = 0xDBB6C0FB;
    uint32_t actualmagic = b->magic;
    
     printf("Actual magic: 0x%X\n", b->magic);
    printf("Expected magic: 0x%X\n", expectedmagic);
    if(actualmagic==expectedmagic)
     { 
      flag=1;
	 }
    printf("\n ");
    return flag;
    
}

// parsing the block for finding the magic number
// Here , we will first check whether the block has Magic Number or not
// If , it is having then we are comparing it actual Magic number

uint64_t parse_block(uint8_t *src, uint64_t sz)
{
    uint8_t *p = src;
    struct block b;
    uint64_t skip = 0;
    uint64_t done = 0;
    uint64_t byte_count = 0;
    struct BolckHeader bh;
    int flagtest;
    
    while (sz > skip) 
	{

        p += skip;
        sz -= skip;
        byte_count += skip;
		b.magic = *((uint32_t *)p);
		if (parse_is_magic(b.magic) != MAGIC_NET_NONE)    // if magic number is there
		{       flagtest= testmagicnum(&b);
		      
                skip = MAGIC_LEN;
                p_blk_s = P_BLK_SZ;

            /* No magic number at this byte, check the next one */
            } 
			else 
			{
                skip = 1;                               
            }
        done += skip;
    }
     if (flagtest)
        printf("\n TEST FOR MAGIC NUMBER FOR  ALL BLOCKs PASSED\n");
    return done;
    
}

uint64_t parse(int blkfd, uint64_t sz)
{
    uint8_t *blk;
    uint64_t done;

    /* Map the input file */
    blk = (uint8_t *)mmap(NULL, sz, PROT_READ, MAP_PRIVATE, blkfd, 0);

    /* Process each block in this file */
    done = parse_block(blk, sz);
    
    
}
    
int main(int argc, char *argv[])
{
    DIR *datadir = NULL;
    struct dirent *dp = NULL;
    struct stat sb;
    int fd;
    int ret = 0;

    if (argc == 2) {

        /* Open the blockchain data directory */
        datadir = opendir(argv[1]);
        if (datadir == NULL) {
            perror("opendir");
            ret = 1;

        } else {

            chdir(argv[1]);

            do {
                errno = 0;
                
                dp = readdir(datadir);
                if (dp != NULL) {
                    if (memcmp(dp->d_name, "blk", 3) == 0) {
                        
                        /* 
                         * NOTE: We are not bothering to sort by filename because we
                         * assume the blockchain files have ascending inode numbers due
                         * to the way they were created. Other sources may require more
                         * sorting.
                         */
                        /* printf("%d\n", dp->d_ino); */

                        fd = open(dp->d_name, O_RDONLY);
                        if (fd < 0) {
                            perror("open");
                        } else {
                            ret = fstat(fd, &sb);
                            if (ret < 0) {
                                perror("stat");
                            } else {
                                /* printf("%s\n", dp->d_name); */
                                parse(fd, (uint64_t)sb.st_size);
                            }
                            close(fd);
                        }
                    }
                } else {
                    if (errno != 0) {
                        perror("readdir");
                    }
                }
            } while (dp != NULL && datadir != NULL);

        }
        
        closedir(datadir);

    } else {
        ret = 1;
    }

    if (ret != 0) {
        printf("Usage: %s /path/to/blockchain/datadir\n", argv[0]);
    }

    return ret; 
}
