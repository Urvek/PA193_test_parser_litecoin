#ifndef BLOCKSTRUCTURE_H_
#define BLOCKSTRUCTURE_H_
#include <stdint.h>
#define MAGIC_MAIN      0xDBB6C0FB
#define MAGIC_TESTNET   0xDCB7C1FC
#define MAGIC_TESTNET3  0x0709110B
#define MAGIC_NAMECOIN  0xFEB4BEF9

/* Helper enum for keeping track of which network a msg came from */
enum magic_net {
	MAGIC_NET_NONE,
	MAGIC_NET_MAIN,
	MAGIC_NET_TESTNET,
	MAGIC_NET_TESTNET3,
	MAGIC_NET_NAMECOIN
};

#define CMD_LEN         12
#define MAGIC_LEN       4
#define BLKSZ_LEN       4
#define VERSION_LEN     4
#define HASH_LEN        32
#define TIME_LEN        4
#define DIFFICULTY_LEN  4
#define NONCE_LEN       4
#define INDEX_LEN       4
#define VALUE_LEN       8
#define SEQUENCE_LEN    4
#define LOCKTIME_LEN    4

// Structure of Input Transaction

 struct transaction_input
{

	// Hash of previous transaction

	uint8_t hash_prev_transaction[32];

	// The index of the specific output in the previous transaction 
	uint32_t index;

	//  The length of the input script

	uint64_t input_script_length;

	// input script for validating complete block chain

	uint8_t *inputscript;

	// sequence number

	uint32_t sequence;

	struct transaction_input *next;
 };

// Structure of output Transaction

 struct transaction_output
{

	// output value 

	uint64_t value;

	// Length of output script

	uint64_t output_script_length;

	// output script

	uint8_t *outputscript;

	struct transaction_output  *next;
};


// Structure for transactions

 struct transaction_structure
{

	// 4 byte transaction version number

	uint32_t transaction_version;

	// number of transaction inputs

	uint64_t transactioninput_count;

	// list of input transactions

	struct transaction_input txin;

	// number of transaction outputs

	uint64_t transactionoutput_count;

	// list of output transactions

	struct transaction_output txout;

	// lock time of transaction

	uint32_t transaction_locktime;
};


// defining the structure of block

 struct block_structure

{

	// Magic number 0xDBB6C0FB

	uint32_t magicnum;

	// size of block typically telling the length of block

	uint32_t blocksize;

	// version number in block chain genrally 1

	uint32_t version;

	// 32 byte hash of previous block

	uint8_t hash_prev_block[32];

	// 32 byte hash  Merkle root ofr verification of comple chain

	uint8_t hash_merkle_root[32];

	// 4 byte timestamp (32 bits) indicating when the block was created

	uint32_t time;

	// 4 byte difficulty target for current block

	uint32_t current_target;

	// 4 byte random number used for mining process

	uint32_t nonce;

	// 8 byte transaction counter for counting the number of transactions

	uint64_t transaction_counter;

	// structure for transactions 

	struct tx *transactionlist;

};


#endif