#include "sha3.h"
#include <cstdlib>
#include <cstring>

//SHA3(KECCAK)内部定義
//KECCAK-f[1600]を使用する
//SHA3_WORD = (1600 / (5 * 5)) / 8
//SHA3_ROUND = 12 + 2 * log2(SHA3_WORD * 8)
constexpr auto SHA3_WORD = sizeof(uint64_t);
constexpr auto SHA3_BLOCKSIZE = (25 * SHA3_WORD);
constexpr auto SHA3_ROUND = 24;

//巡回インデックス定義
static const int c_anIndexM1M5[5] = { 4, 0, 1, 2, 3 }; //c_anIndexM1M5[n] = (n - 1) mod 5
static const int c_anIndexP1M5[5] = { 1, 2, 3, 4, 0 }; //c_anIndexP1M5[n] = (n + 1) mod 5
static const int c_anIndexP2M5[5] = { 2, 3, 4, 0, 1 }; //c_anIndexP2M5[n] = (n + 2) mod 5
static const int c_aanIndex2XP3YM5[5][5] = { { 0, 2, 4, 1, 3 }, { 3, 0, 2, 4, 1 }, { 1, 3, 0, 2, 4 }, { 4, 1, 3, 0, 2 }, { 2, 4, 1, 3, 0 } }; //[y][x], c_aanIndex2XP3YM5[y][x] = (2x + 3y) mod 5
static const int c_aanIndexInvMatX[5][5] = { { 0, 1, 2, 3, 4 }, { 3, 4, 0, 1, 2 }, { 1, 2, 3, 4, 0 }, { 4, 0, 1, 2, 3 }, { 2, 3, 4, 0, 1 } }; //[y][x], c_aanIndexInvMatX[y][x] = ( x + 3y) mod 5

//巡回シフト数定義
static const int c_aanRotateCount[5][5] = { {  0,  1, 62, 28, 27 }, { 36, 44,  6, 55, 20 }, {  3, 10, 43, 25, 39 }, { 41, 45, 15, 21, 8 }, { 18,  2, 61, 56, 14 } }; //[y][x]

//ラウンド定数定義
static const uint64_t c_anRoundConstant[24] = {
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
	0x000000000000800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

//LittleEndianに変換
static inline uint64_t SetLittleEndian(uint64_t nValue)
{
	return nValue;
}

//左方向回転シフト
static inline uint64_t RotateLeft(uint64_t ui64Value, unsigned int uiShift)
{
#if defined(_WIN64) | defined(_WIN32)
	return _rotl64(ui64Value, uiShift);
#else
	return (ui64Value << uiShift) | (ui64Value >> (64 - uiShift));
#endif //defined(_WIN64) | defined(_WIN32)
}

//SHA3更新処理
void SHA3Update(uint64_t state[25])
{
#ifdef _WIN64
#define A(x,y)		ep1[(x) + (y) * 5]
#define E(x,y)		ep2[(x) + (y) * 5]

	uint64_t B[5], C[5], D[5], work[25]; uint64_t* ep1, * ep2, * ep; size_t rnd; uint32_t x, y, xp, yp;

	ep1 = &state[0]; ep2 = &work[0];
	for (rnd = 0; rnd < SHA3_ROUND; rnd++) {
		for (x = 0; x < 5; x++) { C[x] = A(x, 0) ^ A(x, 1) ^ A(x, 2) ^ A(x, 3) ^ A(x, 4); }
		for (x = 0; x < 5; x++) { D[x] = C[c_anIndexM1M5[x]] ^ RotateLeft(C[c_anIndexP1M5[x]], 1); }

		for (y = 0; y < 5; y++) {
			for (x = 0; x < 5; x++) {
				xp = c_aanIndexInvMatX[y][x]; yp = x;
				B[x] = RotateLeft(A(xp, yp) ^ D[xp], c_aanRotateCount[yp][xp]);
			}
			for (x = 0; x < 5; x++) {
				E(x, y) = B[x] ^ ((~B[c_anIndexP1M5[x]]) & B[c_anIndexP2M5[x]]);
			}
		}
		E(0, 0) ^= c_anRoundConstant[rnd];
		ep = ep1; ep1 = ep2; ep2 = ep;
	}

#undef A
#undef E

#else
#define A(x,y)		state[(x) + (y) * 5]
#define B(x,y)		work[(x) + (y) * 5]
	uint64_t C[5]{}, D[5]{}, work[25]{}; uint64_t n, m; size_t rnd; uint32_t x, y;

	for (rnd = 0; rnd < SHA3_ROUND; rnd++) {
		//θ step
		for (x = 0; x < 5; x++) { C[x] = A(x, 0) ^ A(x, 1) ^ A(x, 2) ^ A(x, 3) ^ A(x, 4); }
		for (x = 0; x < 5; x++) { D[x] = C[c_anIndexM1M5[x]] ^ RotateLeft(C[c_anIndexP1M5[x]], 1); }
		for (x = 0; x < 5; x++) {
			for (n = D[x], y = 0; y < 5; y++) {
				A(x, y) ^= n;
			}
		}

		//ρ and π steps
		for (y = 0; y < 5; y++) {
			for (x = 0; x < 5; x++) {
				B(y, c_aanIndex2XP3YM5[y][x]) = RotateLeft(A(x, y), c_aanRotateCount[y][x]);
			}
		}

		//χ step
		for (y = 0; y < 5; y++) {
#if 0
			for (x = 0; x < 5; x++) {
				A(x, y) = B(x, y) ^ ((~B(c_anIndexP1M5[x], y)) & B(c_anIndexP2M5[x], y));
			}
#else
			n = ~B(2, y); m = ~B(4, y);
			A(0, y) = ~(B(0, y) ^ ((B(1, y) | n)));
			A(1, y) = (B(1, y) ^ ((n & B(3, y))));
			A(2, y) = ~(B(2, y) ^ ((B(3, y) | m)));
			A(3, y) = (B(3, y) ^ ((m & B(0, y))));
			A(4, y) = (m ^ ((B(0, y) | ~B(1, y))));
#endif
		}

		//ι step
		A(0, 0) ^= c_anRoundConstant[rnd];
	}
#undef B
#undef A

#endif
}

//SHA3初期化
int SHA3Init(SHA3_CTX* context, size_t hashbitlen, size_t blockbytelen)
{
	if (context == NULL) return 0;

	memset(context, 0x00, sizeof(SHA3_CTX));
	context->nHashLength = hashbitlen / 8;
	if (blockbytelen == 0) {
		if (SHA3_BLOCKSIZE < 2 * context->nHashLength) return 0;
		context->nBlockLength = SHA3_BLOCKSIZE - 2 * context->nHashLength;
	}
	else {
		if (SHA3_BLOCKSIZE < blockbytelen) return 0;
		context->nBlockLength = blockbytelen;
	}
	context->nBlockCount = (context->nBlockLength + SHA3_WORD - 1) / SHA3_WORD;
	return 1;
}

void SHA3Load(SHA3_CTX* context, const unsigned char* data, size_t len)
{
	unsigned char* block; size_t blen, chr, rsize, i;

	if (context == NULL || data == NULL) return;

	block = (unsigned char*)&(context->aui64Block[0]);
	blen = context->nBlockLength; chr = context->nBlockCursor;
	while (len > 0) {
		rsize = (len < blen - chr) ? len : (blen - chr);
		memcpy(block + chr, data, rsize);
		chr += rsize; data = data + rsize; len -= rsize;
		if (chr == blen) {
			for (i = 0; i < context->nBlockCount; i++) {
				context->aui64State[i] ^= SetLittleEndian(context->aui64Block[i]);
			}
			SHA3Update(context->aui64State);
			chr = 0;
		}
	}
	context->nBlockCursor = chr;
}

void SHA3Final(unsigned char* digest, SHA3_CTX* context)
{
	size_t len, size, i; uint64_t hashbuf[25], retbuf[25]{};
	const uint8_t cZero = 0x00; const uint8_t cOne = 0x01; uint8_t cEnd = 0x80;

	if (context == NULL) return;

	if (context->nBlockCursor != context->nBlockLength - 1) {
		SHA3Load(context, &cOne, sizeof(cOne));
		while (context->nBlockCursor != context->nBlockLength - 1) SHA3Load(context, &cZero, sizeof(cZero));
	}
	else { cEnd ^= cOne; }
	SHA3Load(context, &cEnd, sizeof(cEnd));

	memcpy(hashbuf, context->aui64State, sizeof(hashbuf)); len = context->nHashLength;
	do {
		size = len <= context->nBlockLength ? len : context->nBlockLength;
		for (i = 0; i < context->nBlockCount; i++) { retbuf[i] = SetLittleEndian(hashbuf[i]); }
		memcpy(digest, retbuf, size);

		if (size >= len) break;
		SHA3Update(hashbuf); len -= size; digest = digest + size;
	} while (1);
}

void SHA3_224(void* _data, size_t _len, void* _hash)
{
	SHA3_CTX sha3;
	SHA3Init(&sha3, 224, 0);
	SHA3Load(&sha3, (const unsigned char*)_data, _len);
	SHA3Final((unsigned char*)_hash, &sha3);
}

void SHA3_256(void* _data, size_t _len, void* _hash)
{
	SHA3_CTX sha3;
	SHA3Init(&sha3, 256, 0);
	SHA3Load(&sha3, (const unsigned char*)_data, _len);
	SHA3Final((unsigned char*)_hash, &sha3);
}

void SHA3_384(void* _data, size_t _len, void* _hash)
{
	SHA3_CTX sha3;
	SHA3Init(&sha3, 384, 0);
	SHA3Load(&sha3, (const unsigned char*)_data, _len);
	SHA3Final((unsigned char*)_hash, &sha3);
}

void SHA3_512(void* _data, size_t _len, void* _hash)
{
	SHA3_CTX sha3;
	SHA3Init(&sha3, 512, 0);
	SHA3Load(&sha3, (const unsigned char*)_data, _len);
	SHA3Final((unsigned char*)_hash, &sha3);
}
