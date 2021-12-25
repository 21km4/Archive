#pragma once
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

constexpr auto AES_BLOCK_BYTES = 16;
constexpr auto AES_BLOCK_WORDS = AES_BLOCK_BYTES / sizeof(uint32_t);

typedef struct {
	uint32_t Key[60];
	uint8_t rounds;
} AesCtx;

void AesInitKey(AesCtx* Ctx, const uint8_t* Key, int AesKeyBytes);
void AesEncryptBlock(const AesCtx* const Ctx, void* _block);
void AesDecryptBlock(const AesCtx* const Ctx, void* _block);
size_t AesEncryptCbc(const AesCtx* const Ctx, void* _iv, void* _data, size_t len);
size_t AesDecryptCbc(const AesCtx* const Ctx, void* _iv, void* _data, size_t len);
