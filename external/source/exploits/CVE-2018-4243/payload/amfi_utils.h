
//
//  amfi_utils.h
//  electra
//
//  Created by Jamie on 27/01/2018.
//  Copyright © 2018 Electra Team. All rights reserved.
//


#import <stdio.h>
#import <sys/types.h>

#define MACHO(p) ((*(unsigned int *)(p) & ~1) == 0xfeedface)

int strtail(const char *str, const char *tail);
void getSHA256inplace(const uint8_t* code_dir, uint8_t *out);
uint8_t *getSHA256(const uint8_t* code_dir);
uint8_t *getCodeDirectory(const char* name);

// thx hieplpvip
void inject_trusts(int pathc, const char *paths[]);

// Trust cache types
typedef char hash_t[20];

struct trust_chain {
    uint64_t next;
    unsigned char uuid[16];
    unsigned int count;
} __attribute__((packed));

/*
 Note this patch still came from @xerub's KPPless branch, but detailed below is kind of my adventures which I rediscovered most of what he did
 
 So, as said on twitter by @Morpheus______, iOS 11 now uses SHA256 for code signatures, rather than SHA1 like before.
 What confuses me though is that I believe the overall CDHash is SHA1, but each subhash is SHA256. In AMFI.kext, the memcmp
 used to check between the current hash and the hashes in the cache seem to be this CDHash. So the question is do I really need
 to get every hash, or just the main CDHash and insert that one into the trust chain?
 
 If we look at the trust chain code checker (0xFFFFFFF00637B3E8 6+ 11.1.2), it is pretty basic. The trust chain is in the format of
 the following (struct from xerub, but I've checked with AMFI that it is the case):
 
 struct trust_mem {
 uint64_t next;                 // +0x00 - the next struct trust_mem
 unsigned char uuid[16];        // +0x08 - The uuid of the trust_mem (it doesn't seem important or checked apart from when importing a new trust chain)
 unsigned int count;            // +0x18 - Number of hashes there are
 unsigned char hashes[];        // +0x1C - The hashes
 }
 
 The trust chain checker does the following:
 - Find the first struct that has a count > 0
 - Loop through all the hashes in the struct, comparing with the current hash
 - Keeps going through each chain, then when next is 0, it finishes
 
 UPDATE: a) was using an old version of JTool. Now I realised the CDHash is SHA256
 b) For launchd (whose hash resides in the AMFI cache), the first byte is used as an index sort of thing, and the next *19* bytes are used for the check
 This probably means that only the first 20 bytes of the CDHash are used in the trust cache check
 
 So our execution method is as follows:
 - Calculate the CD Hashes for the target resources that we want to play around with
 - Create a custom trust chain struct, and insert it into the existing trust chain - only storing the first 20 bytes of each hash
 - ??? PROFIT
 */

