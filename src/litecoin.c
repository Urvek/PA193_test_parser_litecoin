#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "format.h"
#include "parse.h"
#include "SHA256.h"
#include <openssl/opensslconf.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/opensslv.h>
#include <array>
#include <map>
#include <iostream>
#include <algorithm>
#include <string>
#include <cassert>
#include <vector>
#include <byteswap.h>

uint32_t blk_cnt = 0;
//lookup-Hashmap.
std::map<std::string, struct BolckHeader> lookup_new;
std::map<unsigned int, std::string> blkno_blkhash_new;
char last_block_hash_str[HASH_LEN*2+1];
enum parse_blk_state p_blk_s = P_BLK_MAGIC;
enum parse_tx_state p_tx_s = P_TX_VERSION;
enum parse_txin_state p_txin_s = P_TXIN_PREV_HASH;
enum parse_txout_state p_txout_s = P_TXOUT_VALUE;
//function prototype
void reverse_byte_array(uint8_t *byte_arr,uint8_t *rev_byte_arr,int size);
uint64_t create_block_lookup(struct block_header_hash blk_hdr, struct BolckHeader bh);
/*
 * Map the magic number into network enumeration
 */

enum magic_net parse_is_magic(uint32_t m)
{
	enum magic_net mn = MAGIC_NET_NONE;
	if (m == MAGIC_MAIN) {
        mn = MAGIC_NET_MAIN;
    } else if (m == MAGIC_TESTNET) {
        mn = MAGIC_NET_TESTNET;
    }
    return mn;
}
uint64_t parse(int blkfd, uint64_t sz)
{
    uint8_t *blk;
    uint64_t done;

    /* Map the input file */
    blk = (uint8_t *)mmap(NULL, sz, PROT_READ, MAP_PRIVATE, blkfd, 0);

    /* Process each block in this file */
    done = parse_block(blk, sz);
    
    buildBlockChain();

    /* Drop the mapping */
    munmap(blk, sz);

    return done;
}
void reverse_byte_array(uint8_t *byte_arr,uint8_t *rev_byte_arr,int size){
	for(int i = 0; i<size;i++){		
		rev_byte_arr[i] = byte_arr[size-1-i];
	}
