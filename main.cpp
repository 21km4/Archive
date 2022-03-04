#include "archive.h"

int Encode(int argc, char** argv)
{
	if (argc == 1)
	{
		std::cout << std::endl;
		std::cout << " Usage: " << argv[0] << " forder(or file) [password] [compress level (0-9)] [is encrypt (1/0)]" << std::endl;
		std::cout << std::endl;
		std::cout << " Ex1: " << argv[0] << " folder word 9 1 (password: word, compress level: max, is encrypt: true)" << std::endl;
		std::cout << " Ex2: " << argv[0] << " file sample 0 0 (password: sample, compress level: uncompressed, is encrypt: false)" << std::endl;
		return -1;
	}
	if (argc > 2) SetArchivePassword(argv[2]);

	if (argc > 4) EncodeArchive(argv[1], argv[3][0] - '0', argv[4][0] - '0');
	else if (argc > 3) EncodeArchive(argv[1], argv[3][0] - '0');
	else EncodeArchive(argv[1]);

	system("pause");
	return 0;
}

int Decode(int argc, char** argv) 
{
	if (argc == 1) 
	{
		std::cout << std::endl;
		std::cout << " Usage: " << argv[0] << " forder(or file) [password]" << std::endl;
		std::cout << std::endl;
		std::cout << " Ex: " << argv[0] << " folder test (password: test)" << std::endl;
		return -1;
	}
	if (argc > 2) SetArchivePassword(argv[2]);
	if (!DecodeArchive(argv[1])) std::cout << "Invalid password" << std::endl;
	system("pause");
	return 0;
}

int main(int argc, char** argv)
{
	return Encode(argc, argv);
	return Decode(argc, argv);
}
