#include "AESCipher.h"

AESCipher::AESCipher()
{ }

bool AESCipher::EnDeCrypt(const std::string& fileName, const std::string& key)
{
	std::ifstream ifs(fileName, std::ios::binary); // input file
	// if input file not opened, return false
	if (!ifs.is_open()) 
		return false;

	std::ofstream ofs(inv_file_name(fileName), std::ios::binary); // output file

	void(AESCipher::*crypt)(block&);
	// if "fileName" is encrypted we need decrypt and on the contrary
	if (is_encrypted(fileName))
		crypt = &AESCipher::decrypt;
	else
		crypt = &AESCipher::encrypt;

	const size_t STATES_COUNT = 8; // states from file for encrypt/decrypt 
	block state(NB, word(NB, 0)); // reserve 4x4 
	int b; // one byte from file

	// generate round keys
	key_expansion(key);

	// encrypt/decrypt first 128 bytes from file
	for (int ii = 0; ii < STATES_COUNT; ++ii)
	{
		// copy 16 bytes from file to state
		for (int i = 0; i < NB; ++i)
		{
			for (int j = 0; j < NB; ++j)
			{
				b = ifs.get();

				if (b != -1)
					state[j][i] = b;
				else
					state[j][i] = 0;
			}
		}
		// encrypt/decrypt 16 bytes from file
		(this->*crypt)(state);
		// write result to new file
		for (int i = 0; i < NB; ++i)
		{
			for (int j = 0; j < NB; ++j)
				ofs.put(state[j][i]);
		}
	}

	// appends the rest of file
    const size_t buff_size = 1024 * 1024;
	char buffer[buff_size];

	while (!ifs.eof())
	{
		ifs.read(buffer, buff_size);
		ofs.write(buffer, ifs.gcount());
	}

	// close files
	ifs.close();
	ofs.close();

    // remove file
    RemFile::removeFile(fileName);

	return true;
}

std::string AESCipher::encrypt(const std::string& str, const std::string& key)
{
	threedimarray states = split(str); // split str to states
	key_expansion(key); // generate round keys

	std::string encryptedStr = ""; // encryption result

	for (int i = 0; i < states.size(); ++i)
	{
		encrypt(states[i]); // encrypt one block
		// save result to encryptedStr
		for (int j = 0; j < NB; ++j)
		{
			for (int k = 0; k < NB; ++k)
				encryptedStr += states[i][k][j];
		}
	}

	return str_to_hex(encryptedStr);
}

std::string AESCipher::decrypt(const std::string& str, const std::string& key)
{
	threedimarray states = split(hex_to_str(str)); // split str to states
	key_expansion(key); // generate round keys

	std::string decryptedStr = ""; // decryption result

	for (int i = 0; i < states.size(); ++i)
	{
		decrypt(states[i]); // decrypt one block
		// save result to decryptedStr
		for (int j = 0; j < NB; ++j)
		{
			for (int k = 0; k < NB; ++k)
				decryptedStr += states[i][k][j];
		}
	}

	return decryptedStr;
}

///////////////////////////////////////////////////////////////////////////////////////////////////

bool AESCipher::is_encrypted(const std::string& fileName)
{
    const std::string ext = ".aes";

    if (fileName.size() < ext.size())
        return false;

    for (int i = ext.size(); i >= 0; --i)
        if (fileName[fileName.size() - ext.size() + i] != ext[i])
            return false;
    return true;
}

std::string AESCipher::inv_file_name(const std::string& fileName)
{
    const std::string ext = ".aes";

    if (is_encrypted(fileName))
        return std::string(std::begin(fileName), std::end(fileName) - ext.size());
    else
        return fileName + ext;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////// PRIVATE ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////

void AESCipher::encrypt(block& state)
{
	add_round_key(state, 0);

	for (int round = 1; round < NR; ++round)
	{
		sub_bytes(state);
		shift_rows(state);
		mix_columns(state);
		add_round_key(state, round);
	}

	sub_bytes(state);
	shift_rows(state);
	add_round_key(state, NR);
}

void AESCipher::decrypt(block& state)
{
	add_round_key(state, NR);

	for (int round = NR - 1; round > 0; --round)
	{
		inv_shift_rows(state);
		sub_bytes(state, true);
		add_round_key(state, round);
		inv_mix_columns(state);
	}

	inv_shift_rows(state);
	sub_bytes(state, true);
	add_round_key(state, 0);
}

///////////////////////////////////////////////////////////////////////////////////////////////////

void AESCipher::key_expansion(const std::string& key)
{
    mKeySchedule.clear();

	block keyBlock(NB, word(NB, 0)); // a block of mKeySchedule

	// first block is key
	mKeySchedule.push_back(generate_key(key));
	// fill by 0
	for (int i = 0; i < NR; ++i)
		mKeySchedule.push_back(keyBlock);

	// generate other blocks
	word t;
	byte tmp;

	for (int i = 1; i < mKeySchedule.size(); ++i)
	{
		for (int j = 0; j < NB; ++j)
		{
			if (j == 0)
			{
				t = mKeySchedule[i - 1][NB - 1];
				// row word for t
				tmp = t[0]; t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = tmp;
				// sub word for t
				for (int k = 0; k < t.size(); ++k)
					t[k] = get_sbox(t[k]);
				// xor
				for (int k = 0; k < t.size(); ++k)
					mKeySchedule[i][j][k] = mKeySchedule[i - 1][0][k] ^ t[k] ^ AESArrays::RCON[i][k];
			}
			else
			{
				for (int k = 0; k < t.size(); ++k)
					mKeySchedule[i][j][k] = mKeySchedule[i - 1][0][k] ^ mKeySchedule[i - 1][NB - 1][k];
			}
		}
	}
}

void AESCipher::sub_bytes(block& state, bool inv)
{
	for (int j = 0; j < NB; ++j)
	{
		for (int k = 0; k < NB; ++k)
			state[j][k] = inv ? get_sbox(state[j][k], true) : get_sbox(state[j][k]);
	}
}

void AESCipher::shift_rows(block& state)
{
	byte tmp;

	// first row 
	tmp         = state[1][0];
	state[1][0] = state[1][1];
	state[1][1] = state[1][2];
	state[1][2] = state[1][3];
	state[1][3] = tmp;
	// second row
	tmp         = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = tmp;
	tmp         = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = tmp;
	// third row
	tmp         = state[3][0];
	state[3][0] = state[3][3];
	state[3][3] = state[3][2];
	state[3][2] = state[3][1];
	state[3][1] = tmp;
}

void AESCipher::inv_shift_rows(block& state)
{
	byte tmp;

	// first row 
	tmp         = state[1][3];
	state[1][3] = state[1][2];
	state[1][2] = state[1][1];
	state[1][1] = state[1][0];
	state[1][0] = tmp;
	// second row
	tmp         = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = tmp;
	tmp         = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = tmp;
	// third row
	tmp         = state[3][0];
	state[3][0] = state[3][1];
	state[3][1] = state[3][2];
	state[3][2] = state[3][3];
	state[3][3] = tmp;
}

// xtime is a macro that finds the product of {02} and the argument to xtime modulo {1b}  
#define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x1b))
// multiplty is a macro used to multiply numbers in the field GF(2^8)
#define multiply(x,y) (((y & 1) * x) ^ ((y>>1 & 1) * xtime(x)) ^ ((y>>2 & 1) * xtime(xtime(x))) ^ ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^ ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))

// I really don't understand what this macro do :( 
// I just copied it from http://comp.ist.utl.pt/ec-csc/Code/Ciphers/

void AESCipher::mix_columns(block& state)
{
	byte tmp, tm, t;

	for (int j = 0; j < NB; ++j)
	{
		t   = state[0][j];
		tmp = state[0][j] ^ state[1][j] ^ state[2][j] ^ state[3][j];

		tm = state[0][j] ^ state[1][j]; tm = xtime(tm); state[0][j] ^= tm ^ tmp;
		tm = state[1][j] ^ state[2][j]; tm = xtime(tm); state[1][j] ^= tm ^ tmp;
		tm = state[2][j] ^ state[3][j]; tm = xtime(tm); state[2][j] ^= tm ^ tmp;

		tm = state[3][j] ^ t; 
		tm = xtime(tm);

		state[3][j] ^= tm ^ tmp;
	}
}

void AESCipher::inv_mix_columns(block& state)
{
	byte a, b, c, d;

	for (int j = 0; j < NB; ++j)
	{
		a = state[0][j];
		b = state[1][j];
		c = state[2][j];
		d = state[3][j];

		state[0][j] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
		state[1][j] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
		state[2][j] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
		state[3][j] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
	}
}

void AESCipher::add_round_key(block& state, int round)
{
	for (int j = 0; j < NB; ++j)
	{
		for (int k = 0; k < NB; ++k)
			state[j][k] ^= mKeySchedule[round][j][k];
	}		
}

///////////////////////////////////////////////////////////////////////////////////////////////////

threedimarray AESCipher::split(const std::string& str)
{
	const size_t STATE_CNT = str.size() / STATE_SIZE; // full blocks count
	block state(NB, word(NB, 0)); // a block

	threedimarray states;
	int textPos = 0; // inner loop var for pos of str

	for (int i = 0; i < STATE_CNT; ++i)
	{
		for (int j = 0; j < NB; ++j)
			for (int k = 0; k < NB; ++k)
				state[k][j] = str[textPos++];
		states.push_back(state);
	}

	if (textPos == str.size())
		return states;

	// add last block (supplemented by 0)
	for (int j = 0; j < NB; ++j)
	{
		for (int k = 0; k < NB; ++k)
		{
			if (textPos == str.size())
				state[k][j] = 0;
			else
				state[k][j] = str[textPos++];
		}
	}
	states.push_back(state);

	return states;
}

block AESCipher::generate_key(const std::string& key)
{
    std::string md5Key = MD5::hash(key); // MD5(key)

	// init keyBlock by 0. 4x4 array
	block keyBlock(NB, word(NB, 0));
	int keyPos = 0;

	for (int i = 0; i < NB; ++i)
	{
		for (int j = 0; j < NB; ++j)
            keyBlock[j][i] = md5Key[keyPos++];
	}

	return keyBlock;
}

int AESCipher::get_sbox(int val, bool inv)
{
	const std::string hexSymb = "0123456789abcdef"; // hex symbols

	std::stringstream ss; // for convert dec to hex
	std::string hexByte; // hex string
	int r, c; // row and col of SBOX or INVSBOX array

	ss << std::hex << val; // dec to hex
	hexByte = ss.str(); // hex to string

	if (hexByte.size() == 1) // if hex result size is 1
		hexByte = "0" + hexByte; // add forward 0

	// replace from sBox array
	r = hexSymb.find(hexByte[0]);
	c = hexSymb.find(hexByte[1]);

	return inv ? AESArrays::INVSBOX[r][c] : AESArrays::SBOX[r][c];
}

///////////////////////////////////////////////////////////////////////////////////////////////////

std::string AESCipher::str_to_hex(const std::string& str)
{
	std::stringstream ss;
	std::string hexStr = "";
	std::string hexNum;
	int hexNumSize;

	for (int i = 0; i < str.size(); ++i)
	{
		ss << std::hex << (int)str[i];
		hexNum = ss.str();
		// add forward 0
		hexNumSize = hexNum.size();
		for (int j = 0; j < CHAR_BIT - hexNumSize; ++j)
			hexNum = "0" + hexNum;
		hexStr += hexNum;
		ss.str("");
	}

	return hexStr;
}

std::string AESCipher::hex_to_str(const std::string& hexStr)
{
	std::string str = "";
	int hexNum;

    for (int i = 0; i < hexStr.size(); i += CHAR_BIT)
    {
        try
        {
            hexNum = std::stoul(hexStr.substr(i, CHAR_BIT), nullptr, 16);
        }
        catch (std::invalid_argument e)
        {
            hexNum = 0;
        }

        str += (char)hexNum;
    }

	return str;
}
