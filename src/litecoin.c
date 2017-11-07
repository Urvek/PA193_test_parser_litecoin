#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

char last_block_hash_str[HASH_LEN*2+1];
enum parse_blk_state p_blk_s = P_BLK_MAGIC;
enum parse_tx_state p_tx_s = P_TX_VERSION;
enum parse_txin_state p_txin_s = P_TXIN_PREV_HASH;
enum parse_txout_state p_txout_s = P_TXOUT_VALUE;
