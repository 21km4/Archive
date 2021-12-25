#pragma once
#include <cstdint>

typedef struct _sha3ctx {
	uint64_t aui64State[25]; //ハッシュ状態
	uint64_t aui64Block[25]; //ハッシュブロック
	size_t nHashLength; //ハッシュ長
	size_t nBlockLength; //ブロック長
	size_t nBlockCount; //ブロック数
	size_t nBlockCursor; //ブロックカーソル
} SHA3_CTX;

int SHA3Init(SHA3_CTX* context, size_t hashbitlen, size_t blockbytelen = 0);
void SHA3Load(SHA3_CTX* context, const unsigned char* data, size_t len);
void SHA3Final(unsigned char* digest, SHA3_CTX* context);

void SHA3_224(void* _data, size_t _len, void* _hash);
void SHA3_256(void* _data, size_t _len, void* _hash);
void SHA3_384(void* _data, size_t _len, void* _hash);
void SHA3_512(void* _data, size_t _len, void* _hash);
