#ifndef AESCIPHER_H
#define AESCIPHER_H

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "AESArrays.h"
#include "MD5.h"
#include "RemFile.h"

using byte          = unsigned char;
using word          = std::vector<byte>;
using block         = std::vector<std::vector<byte>>;
using threedimarray = std::vector<std::vector<std::vector<byte>>>;

class AESCipher
{
public:
	AESCipher();

	// encrypt/decrypt file "fileName" and returns false if operation is failed
	bool EnDeCrypt(const std::string& fileName, const std::string& key);

	// encrypt/decrypt text in str and returns result in hex for encrypt 
	std::string encrypt(const std::string& str, const std::string& key);
	std::string decrypt(const std::string& str, const std::string& key);

	// returns true if fileName extension is .aes
	static bool is_encrypted(const std::string& fileName);
    // returns invert fileName with or without .aes
    static std::string inv_file_name(const std::string& fileName);

private:
	// encrypt one block
	void encrypt(block& state);
	// decrypt one block
	void decrypt(block& state);

	void key_expansion(const std::string& key);
	// set inv to true, if you need invert function
	void sub_bytes(block& state, bool inv = false);
	void shift_rows(block& state);
	void inv_shift_rows(block& state);
	void mix_columns(block& state);
	void inv_mix_columns(block& state);
	void add_round_key(block& state, int round);

	// split str to blocks 4x4 bytes
	threedimarray split(const std::string& str);
	// generate key MD5(key)
	block generate_key(const std::string& key);
	// return value of SBOX or INVSBOX for val
	int get_sbox(int val, bool inv = false);

	// converts string to hex string and hex string to string
	std::string str_to_hex(const std::string& str);
	std::string hex_to_str(const std::string& hexStr);

private:
	static const size_t STATE_SIZE = 0x10;
	// column count of state
	static const size_t NB = 0x4; 
	// key size = 128 bit
	static const size_t NK = 0x4; 
	// round count for 128 bit key
	static const size_t NR = 0xA; 

	// round keys
	threedimarray mKeySchedule;
};

#endif
