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

/*
 * Process a var_int starting at p into dest
 */
uint8_t parse_varint(uint8_t *p, uint64_t *dest)
{
    uint8_t varint = *p;
    uint8_t mv = 1;
    if (varint < VAR_INT_2BYTE) {
        *dest = (uint64_t)varint;
    } else if (varint == VAR_INT_2BYTE) {
        *dest = (uint64_t)( *(uint16_t *)(p+1) );
        mv += 2;
    } else if (varint == VAR_INT_4BYTE) {
        *dest = (uint64_t)( *(uint32_t *)(p+1) );
        mv += 4;
    } else if (varint == VAR_INT_8BYTE) {
        *dest = (uint64_t)( *(uint64_t *)(p+1) );
        mv += 8;
    }

    return mv;
}

/*
Generate Hash and create lookup.
*/
uint64_t create_block_lookup(struct block_header_hash blk_hdr, struct BolckHeader bh){
	uint64_t done = 0;
	uint8_t block_hash[HASH_LEN],rev_block_hash[HASH_LEN];	
	computeSHA256((uint8_t*)&blk_hdr,sizeof(struct block_header_hash),block_hash);
	computeSHA256(block_hash,32,block_hash);
	
	reverse_byte_array(block_hash,rev_block_hash,HASH_LEN);
	for(int i=0;i<HASH_LEN;i++){
		sprintf(last_block_hash_str+i*2,"%02x",rev_block_hash[i]);
	}
	last_block_hash_str[HASH_LEN*2]=0;
	
	printf("%s\n",last_block_hash_str);
	//getchar();
			
	lookup_map.insert(std::pair<std::string, struct BolckHeader>(last_block_hash_str,bh));

	blkno_blkhash_map.insert(std::pair<unsigned int, std::string>(bh.blk_cnt,last_block_hash_str));
	return done;
}

void buildBlockChain(){
	char block_hash_str[HASH_LEN*2+1];
	
	std::vector<struct BolckHeader> chain;
	std::vector<unsigned int> temp;
	strcpy(block_hash_str,last_block_hash_str);
	printf("Building full block-chain.\n");
		
	std::map<std::string, struct BolckHeader>::iterator lookup_itr;
	std::map<unsigned int, std::string>::iterator itr;
	for ( itr = blkno_blkhash_map.end(); itr != blkno_blkhash_map.begin(); itr-- )
	{
		std::cout << itr->first << ':' << itr->second << std::endl ;
		if(std::find(temp.begin(), temp.end(), itr->first)!=temp.end()){
      		continue;
		}
		temp.push_back(itr->first);
		if(itr->first==33419) continue;
		strcpy(block_hash_str,itr->second.c_str());
		while(true){
			lookup_itr = lookup_map.find(block_hash_str);
			if (lookup_itr != lookup_map.end()){
				printf("found!!!\n");
				struct BolckHeader bh = ((struct BolckHeader)lookup_itr->second);
				//push it in chain.
				chain.push_back(bh);
				//push block count in temp.
				temp.push_back(bh.blk_cnt);
				for(int i=0;i<HASH_LEN;i++){
					sprintf(block_hash_str+i*2,"%02x",bh.prev_block_hash[i]);
				}
				block_hash_str[HASH_LEN*2]=0;
				int ret = strcmp(block_hash_str,"0000000000000000000000000000000000000000000000000000000000000000");
				if(ret==0){
					printf("Genesis block found!!!");
					break;
				}				
			}else{	
				printf("Not found!!!\n");		
				break;
			}
    	}
    	getchar();
    	for (std::vector<struct BolckHeader>::iterator it = chain.begin() ; it != chain.end(); ++it){
			std::cout << (*it).blk_cnt<< ' ';
		}
    	std::cout << std::endl;
    	chain.clear();
	}
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
