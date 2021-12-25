#pragma once

#include "zlib\zlib.h"
#ifdef _DEBUG
#pragma comment(lib, "MD\\zlibstaticd.lib")
#else
#pragma comment(lib, "MT\\zlibstatic.lib")
#endif

#include <iostream>
#include <string>
#include <vector>

void SetArchivePassword(const std::string& _pass);
void SetArchiveExtension(const std::string& _extension);

bool EncodeArchive(std::string path, int _compress_level = Z_DEFAULT_COMPRESSION, bool _encrypt = true);
bool DecodeArchive(std::string path);
bool CheckArchive(std::string path);
size_t GetDataFromArchive(std::string path, void* dest, std::string archive = "");