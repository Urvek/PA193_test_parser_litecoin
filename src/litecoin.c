#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
//#include <io.h>
#include "format.h"
#include "parse.h"
//#include "mman.h"
//#include "mman.c"
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

//lookup-Hashmap.
std::map<std::string, struct BolckHeader> lookup_map;
std::map<unsigned int, std::string> blkno_blkhash_map;
uint32_t blk_cnt = 0;
char last_block_hash_str[HASH_LEN*2+1];
enum parse_blk_state p_blk_s = P_BLK_MAGIC;
enum parse_tx_state p_tx_s = P_TX_VERSION;
enum parse_txin_state p_txin_s = P_TXIN_PREV_HASH;
enum parse_txout_state p_txout_s = P_TXOUT_VALUE;

void reverse_byte_array(uint8_t *byte_arr,uint8_t *rev_byte_arr,int size);

int validate_merkle_root();
/*
 * Map the magic number into network enumeration
 */
enum magic_net
parse_is_magic(uint32_t m)
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
uint8_t
parse_varint(uint8_t *p, uint64_t *dest)
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
 * Print what we know about a given tx_input
 */
void
parse_txin_print(struct tx_input *i)
{
    uint8_t j;

    printf("    prev output: ");
    for (j=HASH_LEN-1; j<HASH_LEN; j--) {
        printf("%02X", i->prev_hash[j]);
    }
    printf("\n");
    printf("    index: %d\n", i->index);
    printf("    script len: %lu\n", i->script_len);
    printf("    sequence: %X\n", i->sequence);
    printf("\n");
}
/*
 * Print what we know about a given tx_output
 */
void
parse_txout_print(struct tx_output *o)
{
    printf("    value: %lu\n", o->value);
    printf("    script len: %lu\n", o->script_len);
    printf("\n");
}
/*
 * Print what we know about a given bitcoin transaction
 */
void
parse_tx_print(struct tx *t)
{
    printf("  version: %u\n", t->version);
    printf("  txin cnt: %lu\n", t->txin_cnt);
    printf("  txout cnt: %lu\n", t->txout_cnt);
    printf("  lock time: %u\n", t->lock_time);
    printf("\n");
}

/*
 * Print what we know about a block in the blockchain
 */
void
parse_block_print(struct block *b)
{
    time_t t = b->blk_hash.time;
    struct tm *tm = gmtime(&t);
    char timestr[32];
    uint8_t i;
    
    strftime(timestr, 32, "%Y-%m-%d %H:%M:%S", tm);

    printf("magic: 0x%X\n", b->magic);
    printf("size: %u\n", b->size);
    printf("version: %u\n", b->blk_hash.version);
    printf("prev block: ");
    /* Print the hashes in the correct endianness */
    for (i=HASH_LEN-1; i<HASH_LEN; i--) {
        printf("%02X", b->blk_hash.prev_block[i]);
    }
    printf("\n");
    printf("merkle root: ");
    for (i=HASH_LEN-1; i<HASH_LEN; i--) {
        printf("%02X", b->blk_hash.merkle_root[i]);
    }
    printf("\n");
    printf("time: %s\n", timestr);
    printf("bits: %u\n", b->blk_hash.bits);
    printf("nonce: %u\n", b->blk_hash.nonce);
    printf("tx count: %lu\n", b->tx_cnt);
    printf("\n");
}

/*
 * Parse count tx_inputs from the stream starting at p
 * Return the number of bytes processed
 */
uint64_t
parse_txin(uint8_t *src, uint64_t count)
{
    uint8_t *p = src;
    struct tx_input i;
    uint64_t skip = 0;
    uint64_t done = 0;

    p_txin_s = P_TXIN_PREV_HASH;

    while (count > 0) {

        p += skip;

        switch (p_txin_s) {

        case P_TXIN_PREV_HASH:
            memcpy((void *)&i.prev_hash, p, HASH_LEN);
            skip = HASH_LEN;
            p_txin_s = P_TXIN_INDEX;
            break;

        case P_TXIN_INDEX:
            i.index = *(uint32_t *)p;
            skip = INDEX_LEN;
            p_txin_s = P_TXIN_SCRIPT_LEN;
            break;

        case P_TXIN_SCRIPT_LEN:
            skip = (uint64_t)parse_varint(p, &(i.script_len));
            p_txin_s = P_TXIN_SCRIPT;
            break;

        case P_TXIN_SCRIPT:
            i.script = p;
            skip = i.script_len;
            p_txin_s = P_TXIN_SEQUENCE;
            break;

        case P_TXIN_SEQUENCE:
            i.sequence = *(uint32_t *)p;
            skip = SEQUENCE_LEN;
            //parse_txin_print(&i);
            count--;
            p_txin_s = P_TXIN_PREV_HASH;
            break;

        default:
            break;
        }

        done += skip;
    }

    return done;
}

/*
 * Parse count tx_outputs from the stream starting at p
 * Return the number of bytes processed
 */
uint64_t
parse_txout(uint8_t *src, uint64_t count)
{
    uint8_t *p = src;
    struct tx_output o;
    uint64_t skip = 0;
    uint64_t done = 0;

    p_txout_s = P_TXOUT_VALUE;

    while (count > 0) {

        p += skip;

        switch (p_txout_s) {

        case P_TXOUT_VALUE:
            o.value = *(uint64_t *)p;
            skip = VALUE_LEN;
            p_txout_s = P_TXOUT_SCRIPT_LEN;
            break;

        case P_TXOUT_SCRIPT_LEN:
            skip = (uint64_t)parse_varint(p, &(o.script_len));
            p_txout_s = P_TXOUT_SCRIPT;
            break;

        case P_TXOUT_SCRIPT:
            o.script = p;
            skip = o.script_len;
            //parse_txout_print(&o);
            count--;
            p_txout_s = P_TXOUT_VALUE;
            break;

        default:
            break;
        }

        done += skip;
    }

    return done;
}
/*
 * Parse count transactions from the stream starting at p
 * Return number of bytes processed
 */
uint64_t
parse_tx(uint8_t *src, uint64_t count, struct BolckHeader *bhp)
{
    uint8_t *p = src;
    uint8_t *q = src;
    struct tx t;
    uint64_t skip = 0;
    uint64_t done = 0;
    int trans_size = 0;
    uint64_t num_of_trans = count;
    
    uint64_t num_of_hash=count;
    if(count!=1){
    	if(count%2){
    		num_of_hash = count + 1;
		}
	}    
	uint8_t *tran_hash_list[num_of_hash];

	int tran_count=0;
    p_tx_s = P_TX_VERSION;

    while (count > 0) {

        p += skip;

        switch (p_tx_s) {

        case P_TX_VERSION:
            t.version = *(uint32_t *)p;
            skip = VERSION_LEN;
            p_tx_s = P_TX_TXIN_CNT;
            trans_size += skip;
            break;

        case P_TX_TXIN_CNT:
            skip = (uint64_t)parse_varint(p, &(t.txin_cnt));
            p_tx_s = P_TX_TXIN;
            trans_size += skip;
            break;

        case P_TX_TXIN:
            /* Process each input in this transaction */
            skip = parse_txin(p, t.txin_cnt);
            p_tx_s = P_TX_TXOUT_CNT;
            trans_size += skip;
            break;

        case P_TX_TXOUT_CNT:
            skip = (uint64_t)parse_varint(p, &(t.txout_cnt));
            p_tx_s = P_TX_TXOUT;
            trans_size += skip;
            break;

        case P_TX_TXOUT:
            /* Process each output in this transaction */
            skip = parse_txout(p, t.txout_cnt);
            p_tx_s = P_TX_LOCKTIME;
            trans_size += skip;
            break;

        case P_TX_LOCKTIME:
            t.lock_time = *(uint32_t *)p;
            skip = LOCKTIME_LEN;

            //Added for Transction.
            uint8_t *trans_bytes; 
			uint8_t trans_hash[HASH_LEN],rev_trans_hash[HASH_LEN];
			          
            trans_size +=skip;
            
            trans_bytes = (uint8_t *)malloc(trans_size);
            memcpy((void *)trans_bytes, q, trans_size);
            computeSHA256(trans_bytes,trans_size,trans_hash);
            computeSHA256(trans_hash,32,trans_hash);            

           	tran_hash_list[tran_count] = (uint8_t*)malloc(HASH_LEN);
           	
           	memcpy((void *)tran_hash_list[tran_count], trans_hash, HASH_LEN);
           	//for printing hash.
           	reverse_byte_array(tran_hash_list[tran_count],rev_trans_hash,HASH_LEN);
            
			char trans_hash_str[HASH_LEN*2+1];
            for(int i=0;i<HASH_LEN;i++){
				sprintf(trans_hash_str+i*2,"%02x",rev_trans_hash[i]);
			}
			trans_hash_str[HASH_LEN*2]=0;
			
            free(trans_bytes);

            count--;
            tran_count++;
            q = q + trans_size;
            trans_size=0;
            p_tx_s = P_TX_VERSION;
            break;

        default:
            break;
        }

        done += skip;
    }
    //merkle tree
    if(num_of_trans != 1){    	
	    if(num_of_trans%2){
	    	tran_hash_list[tran_count] = (uint8_t*)malloc(HASH_LEN);
	    	memcpy((void *)tran_hash_list[tran_count], tran_hash_list[tran_count-1], HASH_LEN);
		}
		uint64_t loop_ctrl = num_of_hash/2;
		uint64_t i=0;
		while(true){	
			int j=0;
			for(i=0;i<loop_ctrl;i++){
				uint8_t hash_64[HASH_LEN*2];
				uint8_t trans_hash[HASH_LEN];
				memcpy((void *)hash_64, tran_hash_list[j], HASH_LEN);
				memcpy((void *)(hash_64+HASH_LEN), tran_hash_list[j+1], HASH_LEN);

				computeSHA256(hash_64,HASH_LEN*2,trans_hash);
		        computeSHA256(trans_hash,HASH_LEN,trans_hash);
		        memcpy((void *)tran_hash_list[i], trans_hash, HASH_LEN);
		        j=j+2;
				//getchar();
			}
			//check for odd.
			if(loop_ctrl==1){
				break;
			}
			if(loop_ctrl%2){
				loop_ctrl = loop_ctrl +1;
				memcpy((void *)tran_hash_list[i], tran_hash_list[i-1], HASH_LEN);
			}
			loop_ctrl=loop_ctrl/2;
		}
	}
	
//	printf("Calculated:");
	bhp->is_valid = 1;
	reverse_byte_array(tran_hash_list[0],bhp->cal_merkle_root,HASH_LEN);
	for(int k = 0 ; k < HASH_LEN ; k++){
		if(bhp->cal_merkle_root[k] != bhp->merkle_root[k]){
			bhp->is_valid = 0;
			break;
		}
	}

	for(uint64_t i=0;i<num_of_hash;i++){
		free(tran_hash_list[i]);
	}	
    return done;
}
uint64_t
create_block_lookup(struct block_header_hash blk_hdr, struct BolckHeader bh);
/*
 * Parse a series of blockchain blocks between p and end
 * Return the number of bytes processed
 */
uint64_t
parse_block(uint8_t *src, uint64_t sz)
{
    uint8_t *p = src;
    struct block b;
    uint64_t skip = 0;
    uint64_t done = 0;
    uint64_t byte_count = 0;
    struct BolckHeader bh;

    /* Look for different patterns depending on our state */
    while (sz > skip) {

        p += skip;
        sz -= skip;
        byte_count += skip;
		
        switch (p_blk_s) {

        /* Look for the magic number */
        case P_BLK_MAGIC:
            /* Check for magic number */
            b.magic = *((uint32_t *)p);

            /* If blk[i] starts the magic bytes, we can skip ahead */
            if (parse_is_magic(b.magic) != MAGIC_NET_NONE) {
                skip = MAGIC_LEN;
                p_blk_s = P_BLK_SZ;

            /* No magic number at this byte, check the next one */
            } else {
                skip = 1;                               
            }
            break;

        case P_BLK_SZ:
            b.size = *(uint32_t *)p;
            skip = BLKSZ_LEN;
            p_blk_s = P_BLK_VERSION;
            break;

        case P_BLK_VERSION:        	
            b.blk_hash.version = *(uint32_t *)p;
            skip = VERSION_LEN;
            p_blk_s = P_BLK_PREV;
            break;

        case P_BLK_PREV:
            memcpy((void *)&b.blk_hash.prev_block, p, HASH_LEN);
            skip = HASH_LEN;
            p_blk_s = P_BLK_MERKLE;
            break;

        case P_BLK_MERKLE:
            memcpy((void *)&b.blk_hash.merkle_root, p, HASH_LEN);
            skip = HASH_LEN;
            p_blk_s = P_BLK_TIME;
            break;

        case P_BLK_TIME:
            b.blk_hash.time = *(uint32_t *)p;
            skip = TIME_LEN;
            p_blk_s = P_BLK_BITS;
            break;

        case P_BLK_BITS:
            b.blk_hash.bits = *(uint32_t *)p;
            skip = DIFFICULTY_LEN;
            p_blk_s = P_BLK_NONCE;
            break;

        case P_BLK_NONCE:
            b.blk_hash.nonce = *(uint32_t *)p;
            skip = NONCE_LEN;
            p_blk_s = P_BLK_TXCNT;
            
            break;

        case P_BLK_TXCNT:
            skip = (uint64_t)parse_varint(p, &(b.tx_cnt));
            p_blk_s = P_BLK_TX;
            break;

        case P_BLK_TX:
        	
            bh.fph = src;
            
            bh.file_offset = byte_count;
            reverse_byte_array(b.blk_hash.prev_block,bh.prev_block_hash,HASH_LEN);
            
            //added for transction.
            reverse_byte_array(b.blk_hash.merkle_root,bh.merkle_root,HASH_LEN);
            bh.blk_cnt = blk_cnt++;
            
            /* Process each transaction in this block */
            skip = parse_tx(p, b.tx_cnt,&bh);
			//create lookup
            create_block_lookup(b.blk_hash,bh);
			
            //parse_block_print(&b); 
            p_blk_s = P_BLK_MAGIC;

            break;
            
        default:
            break;
        }

        done += skip;
    }

    return done;
}

/*
Generate Hash and create lookup.
*/
uint64_t
create_block_lookup(struct block_header_hash blk_hdr, struct BolckHeader bh){
	uint64_t done = 0;
	uint8_t block_hash[HASH_LEN],rev_block_hash[HASH_LEN];	
	computeSHA256((uint8_t*)&blk_hdr,sizeof(struct block_header_hash),block_hash);
	computeSHA256(block_hash,32,block_hash);
	
	reverse_byte_array(block_hash,rev_block_hash,HASH_LEN);
	for(int i=0;i<HASH_LEN;i++){
		sprintf(last_block_hash_str+i*2,"%02x",rev_block_hash[i]);
	}
	last_block_hash_str[HASH_LEN*2]=0;
	
			
	lookup_map.insert(std::pair<std::string, struct BolckHeader>(last_block_hash_str,bh));

	blkno_blkhash_map.insert(std::pair<unsigned int, std::string>(bh.blk_cnt,last_block_hash_str));
	return done;
}

void buildBlockChain(){
	FILE *bfp,*mfp; 
	char block_hash_str[HASH_LEN*2+1];
	
	std::vector<struct BolckHeader> chain;
	std::vector<struct BolckHeader> final_chain;
	std::vector<unsigned int> temp;
	bfp = fopen("block-chain.txt","w");
	if(!bfp){
		printf("Unable to create block-chain.txt file.\n");
		exit(0);
	}
	mfp = fopen("transaction-validation.txt","w");
	if(!mfp){
		printf("Unable to create transaction-validation.txt file.\n");
		exit(0);
	}
	strcpy(block_hash_str,last_block_hash_str);
	printf("Building full block-chain.\n");
	fprintf(bfp,"Building full block-chain\n");
	
	std::map<std::string, struct BolckHeader>::iterator lookup_itr;
	std::map<unsigned int, std::string>::reverse_iterator itr;
	

	for ( itr = blkno_blkhash_map.rbegin(); itr != blkno_blkhash_map.rend(); ++itr )
	{

		if(std::find(temp.begin(), temp.end(), itr->first)!=temp.end()){
      		continue;
		}
		temp.push_back(itr->first);
		
		strcpy(block_hash_str,itr->second.c_str());
		while(true){
			lookup_itr = lookup_map.find(block_hash_str);
			if (lookup_itr != lookup_map.end()){
//				printf("found!!!\n");
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
//					printf("Genesis block found!!!");
					final_chain.clear();
					final_chain.swap(chain);
					break;
				}
			}else{	
		
				break;
			}
    	}

    	for (std::vector<struct BolckHeader>::iterator it = chain.begin() ; it != chain.end(); ++it){
			std::cout << (*it).blk_cnt<< ' ';
			fprintf(bfp,"%u ",(*it).blk_cnt);
		}
    	std::cout << std::endl;
    	fprintf(bfp,"\n\n");
    	chain.clear();
	}
	
	for (std::vector<struct BolckHeader>::iterator it = final_chain.begin() ; it != final_chain.end(); ++it){
		std::cout << (*it).blk_cnt<< ' ';
		fprintf(bfp,"%u ",(*it).blk_cnt);
	}
	
	std::cout << std::endl;
	fprintf(bfp,"\n");
	printf("Genesis block found!!!\n\n");
	fprintf(bfp,"Genesis block found!!!\n\n");
	fprintf(bfp,"Total Number of Blocks:%lu\n",blkno_blkhash_map.size());
	printf("Total Number of Blocks:%lu\n",blkno_blkhash_map.size());
	fprintf(bfp,"Total Number of Blocks in Block Chain:%lu\n",final_chain.size());
	printf("Total Number of Blocks in Block Chain:%lu\n",final_chain.size());
	fprintf(bfp,"Total Number of Orphan Blocks:%lu\n",(blkno_blkhash_map.size()-final_chain.size()));
	printf("Total Number of Orphan Blocks:%lu\n",(blkno_blkhash_map.size()-final_chain.size()));
	
	//printing merkle tree.
	fprintf(mfp,"Validation of transaction in block chain\n");
	fprintf(mfp,"Block#     |Validation Result  |   Block Hash  |  Merkle Root in Block | Calculated Merkle Root of Block\n");
	for ( itr = blkno_blkhash_map.rbegin(); itr != blkno_blkhash_map.rend(); ++itr )
	{
		strcpy(block_hash_str,itr->second.c_str());
		lookup_itr = lookup_map.find(block_hash_str);
		struct BolckHeader bh = ((struct BolckHeader)lookup_itr->second);
		fprintf(mfp,"%u | %s | %s | ",bh.blk_cnt,bh.is_valid?"Valid":"Invalid",block_hash_str);
		for(int i=0;i<HASH_LEN;i++) {
			sprintf(block_hash_str+i*2,"%02x",bh.merkle_root[i]);
		}
		block_hash_str[HASH_LEN*2]=0;
		fprintf(mfp,"%s | ",block_hash_str);
		for(int i=0;i<HASH_LEN;i++) {
			sprintf(block_hash_str+i*2,"%02x",bh.cal_merkle_root[i]);
		}
		block_hash_str[HASH_LEN*2]=0;
		fprintf(mfp,"%s \n",block_hash_str);		
	}
	fclose(bfp);
	fclose(mfp);
}

uint64_t
parse(int blkfd, uint64_t sz)
{
    uint8_t *blk;
    uint64_t done;

    /* Map the input file */
    blk = (uint8_t *)mmap(NULL, sz, PROT_READ, MAP_PRIVATE, blkfd, 0);

    /* Process each block in this file */
    done = parse_block(blk, sz);
    
    //iterate through hashmap.
    buildBlockChain();

    /* Drop the mapping */
    munmap(blk, sz);    

    return done;
}

void reverse_byte_array(uint8_t *byte_arr,uint8_t *rev_byte_arr,int size){
	for(int i = 0; i<size;i++){		
		rev_byte_arr[i] = byte_arr[size-1-i];
	}
}


