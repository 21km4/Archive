#include "archive.h"
#include "crypto.h"
#include "sha3.h"
#include <filesystem>
#include <fstream>
#include <random>

static std::string extension = ".dat";
static std::string password;

struct ARCHIVE_HEADER {
	size_t file_num;
	uint16_t pass_md;
	bool is_encrypted;
	bool is_directory;
};

struct FILE_HEADER {
	size_t original_size;
	size_t pressed_size;
	size_t pointer;
	size_t path_size;
};

static inline void XorBits(char* bits, size_t size)
{
	std::mt19937 engine(size);
	for (size_t i = 0; i < size; i++) {
		bits[i] ^= engine() & 0xff;
	}
}

static inline uint16_t GetPassMD() {
	uint16_t md = 0; uint16_t hash[14];
	SHA3_224(password.data(), password.size(), hash);
	for (int i = 0; i < 14; i++) md ^= hash[i];
	return md;
}

static size_t ReadHeader(std::ifstream& ifs, ARCHIVE_HEADER& header, std::vector<FILE_HEADER>& heads, std::vector<std::string>& paths)
{
	ifs.seekg(0, std::ios_base::beg);

	ifs.read((char*)&header, sizeof(ARCHIVE_HEADER));
	XorBits((char*)&header, sizeof(ARCHIVE_HEADER));

	if (header.pass_md != GetPassMD()) return 0;

	heads.resize(header.file_num);
	ifs.read((char*)heads.data(), (uint64_t)sizeof(FILE_HEADER) * header.file_num);
	XorBits((char*)heads.data(), (uint64_t)sizeof(FILE_HEADER) * header.file_num);

	paths.resize(header.file_num);
	for (size_t i = 0; i < header.file_num; i++)
	{
		paths[i].resize(heads[i].path_size);
		ifs.read(paths[i].data(), heads[i].path_size);
		XorBits((char*)paths[i].data(), heads[i].path_size);
	}

	return (size_t)ifs.tellg();
}
static void WriteHeader(std::ofstream& ofs, ARCHIVE_HEADER& header, std::vector<FILE_HEADER>& heads, std::vector<std::string>& paths)
{
	XorBits((char*)&header, sizeof(ARCHIVE_HEADER));
	XorBits((char*)heads.data(), (uint64_t)sizeof(FILE_HEADER) * heads.size());
	for (size_t i = 0; i < paths.size(); i++) XorBits(paths[i].data(), paths[i].size());

	ofs.write((char*)&header, sizeof(ARCHIVE_HEADER));
	ofs.write((char*)heads.data(), (uint64_t)sizeof(FILE_HEADER) * heads.size());
	for (size_t i = 0; i < paths.size(); i++) ofs.write(paths[i].c_str(), paths[i].size());
}

void SetArchivePassword(const std::string& _pass)
{
	password = _pass;
}

void SetArchiveExtension(const std::string& _extension)
{
	extension = _extension;
}

bool GetFileList(std::string path, std::vector<std::string>& list)
{
	for (const auto& file : std::filesystem::recursive_directory_iterator(path))
		if (!file.is_directory()) list.insert(list.end(), file.path().string());
	return true;
}

bool EncodeArchive(std::string path, int _compress_level, bool _encrypt)
{
	const bool is_directory = std::filesystem::is_directory(path);
	const auto cd = std::filesystem::current_path();
	size_t pos = path.find_last_of('\\');

	if (is_directory) {
		std::filesystem::current_path(path);
		std::filesystem::current_path("..");
	}
	else if (std::filesystem::exists(path)) {
		if (pos != std::string::npos) std::filesystem::current_path(path.substr(0, pos));
	}
	else return false;

	if (pos != std::string::npos) path = path.substr(pos + 1);

	std::vector<std::string> paths;
	if (is_directory) GetFileList(path, paths);
	else paths.insert(paths.end(), path);
	if (paths.size() == 0) return false;

	if (is_directory) {
		std::filesystem::current_path(path);
		for (auto& t : paths) t = t.substr(path.size() + 1);
	}

	std::vector<FILE_HEADER> heads;
	heads.resize(paths.size());
	std::vector<uint8_t> data;
	for (size_t i = 0; i < paths.size(); i++)
	{
		heads[i].pointer = data.size();
		heads[i].path_size = paths[i].size();
		heads[i].pressed_size = heads[i].original_size = (size_t)std::filesystem::file_size(paths[i]);
		std::ifstream ifs;
		ifs.open(paths[i], std::ios_base::in | std::ios_base::binary);
		if (!ifs) return false;

		uint8_t* original = new uint8_t[heads[i].original_size];
		uint8_t* encoded;
		ifs.read((char*)original, heads[i].original_size);

		uint8_t hash[48], pass[48];
		SHA3_384((uint8_t*)paths[i].c_str(), paths[i].size(), hash);
		SHA3_384((uint8_t*)password.c_str(), password.size(), pass);
		for (int i = 0; i < 48; i++) hash[i] ^= pass[i];

		AesCtx ctx;
		AesInitKey(&ctx, hash, 32);

		heads[i].pressed_size = heads[i].original_size / 7 * 8 + 1024;
		encoded = new uint8_t[heads[i].pressed_size];
		compress2(encoded, (uLongf*)&heads[i].pressed_size, original, (uLongf)heads[i].original_size, _compress_level);
		if (_encrypt) heads[i].pressed_size = AesEncryptCbc(&ctx, hash + 32, encoded, heads[i].pressed_size);

		data.resize(data.size() + heads[i].pressed_size);
		std::memcpy(data.data() + data.size() - heads[i].pressed_size, encoded, heads[i].pressed_size);

		delete[] original; delete[] encoded;
		ifs.close();

		std::cout << paths[i] << std::endl;
		std::cout << "oroginal size: " << heads[i].original_size << " Byte" << std::endl;
		std::cout << "compressed size: " << heads[i].pressed_size << " Byte" << std::endl;
		std::cout << "compression ratio: " << (float)heads[i].pressed_size / (float)heads[i].original_size * 100.0f << " %" << std::endl;
		std::cout << std::endl;
	}

	ARCHIVE_HEADER header = { paths.size(), GetPassMD(), is_directory, _encrypt };

	if (is_directory) std::filesystem::current_path("..");

	std::ofstream ofs;
	path += extension;
	ofs.open(path, std::ios_base::out | std::ios_base::trunc | std::ios_base::binary);
	if (!ofs) return false;
	WriteHeader(ofs, header, heads, paths);
	ofs.write((char*)data.data(), data.size());
	ofs.close();

	std::filesystem::current_path(cd);
	return true;
}

bool CheckArchive(std::string path)
{
	std::ifstream ifs;
	ifs.open(path, std::ios_base::in | std::ios_base::binary);
	if (!ifs) return false;

	std::vector<FILE_HEADER> head;
	std::vector<std::string> paths;
	ARCHIVE_HEADER header;
	size_t head_size = ReadHeader(ifs, header, head, paths);
	if (head_size == 0) return false;

	std::string first_dir;
	size_t pos = path.find_first_of('\\');
	if (header.is_directory && pos != std::string::npos) first_dir = path.substr(0, pos + 1);	

	for (size_t i = 0; i < head.size(); i++)
	{
		std::cout << first_dir + paths[i] << std::endl;
		std::cout << "oroginal size: " << head[i].original_size << " Byte" << std::endl;
		std::cout << "compressed size: " << head[i].pressed_size << " Byte" << std::endl;
		std::cout << "compression ratio: " << (float)head[i].pressed_size / (float)head[i].original_size * 100.0f << " %" << std::endl;
		std::cout << "pointer: " << head_size + head[i].pointer << std::endl;
		std::cout << std::endl;
	}

	ifs.close();
	return true;
}

size_t GetDataFromArchive(std::string path, void* dest, std::string archive_path)
{
	size_t pos = path.find_first_of('\\');
	if (pos != std::string::npos) archive_path = path.substr(0, pos) + extension;	
	else if (archive_path.empty()) archive_path = path + extension;

	std::ifstream ifs;
	ifs.open(archive_path, std::ios_base::in | std::ios_base::binary);
	if (!ifs) return 0;
	std::vector<FILE_HEADER> head;
	std::vector<std::string> paths;
	ARCHIVE_HEADER header;
	size_t head_size = ReadHeader(ifs, header, head, paths);
	if (head_size == 0) return false;

	std::string first_dir;
	if (header.is_directory) first_dir = path.substr(0, pos + 1);

	size_t size = 0;
	for (size_t i = 0; i < head.size(); i++)
	{
		if (path == first_dir + paths[i])
		{
			size = head[i].original_size;
			if (!dest) return size;

			ifs.seekg((uint64_t)head_size + head[i].pointer, std::ios_base::beg);
			uint8_t* pressed = new uint8_t[head[i].pressed_size];
			uint8_t* original = new uint8_t[head[i].original_size + 1024];
			ifs.read((char*)pressed, head[i].pressed_size);

			uint8_t hash[48], pass[48];
			SHA3_384((uint8_t*)paths[i].c_str(), paths[i].size(), hash);
			SHA3_384((uint8_t*)password.c_str(), password.size(), pass);
			for (int i = 0; i < 48; i++) hash[i] ^= pass[i];

			AesCtx ctx;
			AesInitKey(&ctx, hash, 32);
			if (header.is_encrypted) head[i].pressed_size = AesDecryptCbc(&ctx, hash + 32, pressed, head[i].pressed_size);
			uncompress(original, (uLongf*)&head[i].original_size, pressed, (uLongf)head[i].pressed_size);

			memcpy(dest, original, head[i].original_size);
			delete[] pressed; delete[] original;
			break;
		}
	}

	ifs.close();
	return size;
}

bool DecodeArchive(std::string path)
{
	const auto cd = std::filesystem::current_path();
	size_t pos = path.find_last_of('\\');
	if (pos != std::string::npos) {
		std::filesystem::current_path(path.substr(0, pos));
		path = path.substr(pos + 1);
	}

	std::ifstream ifs;
	ifs.open(path, std::ios_base::in | std::ios_base::binary);
	if (!ifs) return false;

	std::vector<FILE_HEADER> head;
	std::vector<std::string> paths;
	ARCHIVE_HEADER header;
	size_t head_size = ReadHeader(ifs, header, head, paths);
	if (head_size == 0) return false;
	std::string first_dir;
	if (header.is_directory) 
	{
		first_dir = path.substr(0, path.size() - extension.size()) + "\\";
		for (auto& p : paths) p = first_dir + p;
	}

	ifs.close();

	for (size_t i = 0; i < head.size(); i++)
	{
		uint8_t* original = new uint8_t[head[i].original_size];
		if (header.is_directory) GetDataFromArchive(paths[i], original);
		else GetDataFromArchive(paths[i], original, path);

		std::cout << paths[i] << std::endl;
		std::cout << "size: " << head[i].original_size << " Byte" << std::endl;
		std::cout << std::endl;

		size_t pos = paths[i].find_last_of('\\');
		if (pos != std::string::npos) {	
			std::string dir = paths[i].substr(0, pos);			
			if (!std::filesystem::exists(dir)) std::filesystem::create_directories(dir);
		}

		std::ofstream ofs;
		ofs.open(paths[i], std::ios_base::out | std::ios_base::trunc | std::ios_base::binary);
		if (!ofs) return false;
		ofs.write((char*)original, head[i].original_size);
		ofs.close();

		delete[] original;
	}

	std::filesystem::current_path(cd);
	return true;
}