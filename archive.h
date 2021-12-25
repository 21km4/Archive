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

// 第一引数　ファイルのパス（ディレクトリを圧縮した場合はアーカイブファイルの拡張子を除いた部分が最初のディレクトリとなる）
// 第二引数　ファイルデータを受け取るバッファ（あらかじめ確保すること）。NULLやnullptrを指定すればデータサイズのみが返される。
// 第三引数　アーカイブファイルのパス（ディレクトリを圧縮した場合は無視される）アーカイブファイル名の拡張子を除いた部分が圧縮したファイル名と同じなら省略可。
// 戻り値　　データサイズ。パスワードが間違ったりファイルが存在しないときは０を返す。
size_t GetDataFromArchive(std::string path, void* dest, std::string archive_path = "");