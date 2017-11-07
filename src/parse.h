#ifndef PARSE_H_
#define PARSE_H_

enum parse_blk_state {
    P_BLK_MAGIC,
    P_BLK_SZ,
    P_BLK_VERSION,
    P_BLK_PREV,
    P_BLK_MERKLE,
    P_BLK_TIME,
    P_BLK_BITS,
    P_BLK_NONCE,
    P_BLK_TXCNT,
    P_BLK_TX
};
