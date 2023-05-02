#define _CRT_SECURE_NO_WARNINGS // sprintf

#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <map>
#include <random>

using namespace std;

// 함수 원형
string Push_back_Str();
string UtilCipherText(bool isPrint);
string MakeIV();
void Hex16BStringTo4by4Mat(int arr[][4], string value);

int M44[4][4]; // 4by4 Matrix
string plainTxt ; 
string cipherKey; 
vector<string> ctr_output_str; // ctr모드 출력 스트링
vector<string> cbc_output_str; // cbc모드 출력 스트링
vector<string> ecb_output_str; // ecb모드 출력 스트링
vector<string> pt_s_str; // plainTxt32를 두개씩 잘라놓을 임시 변수
vector<string> ck_s_str; // cipherKey32를 두개씩 잘라놓을 임시 변수
vector<int> v_ptHex16;
vector<int> k_ckHex16;
map<int, int> S_Box;
int Key[4][44];
int T[4];


#pragma region S_Box
int S_BoxTable[16][16] = {
	{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
	{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
	{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
	{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
	{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
	{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
	{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
	{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
	{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
	{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
	{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
	{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
	{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
	{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
	{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
	{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
};
int rcon[13] = { 0x01,0x02 ,0x04 ,0x08 ,0x10 ,0x20 ,0x40,0x80,0x1B,0x36 };
#pragma endregion S_Box

void Init__S_boxMappingTable() {
	for (int i = 0; i < 16; ++i) {
		for (int j = 0; j < 16; ++j) {
			S_Box[i * 16 + j] = S_BoxTable[i][j];
		}
	}
}

void CreateState(string str) {
	int count = 0;
	string tmp;
	for (int i = 0; i < 4; ++i){
		for (int j = 0; j < 4; ++j) {
			// stoi를 사용해서 2자리 16진수 문자열을 16진수 정수형으로 전환
			tmp = "";
			for (int k = 0; k < 2; ++k) {
				tmp += str[count];
				count++;
			}
			M44[j][i] = stoi(tmp, nullptr, 16);
		}
	}
}


void AddRoundKey(int n) {
	for (int i = 0; i < 4; ++i) {
		for (int j = 0; j < 4; ++j) {
			M44[i][j] ^= Key[i][n*4 + j];
		}
	}
}
// 검증완료
void SubBytes() {
	for (int i = 0; i < 4; ++i) {
		for (int j = 0; j < 4; ++j) {
			M44[i][j] = S_Box[M44[i][j]];
		}
	}
}
// 검증완료
void ShiftRows() {
	// i = 0일 때 그대로 두므로 Skip
	int TM44[4][4]; // 임시 4by4 Matrix
	for (int i = 1; i < 4; ++i) {
		for (int j = i; j < 4 + i; ++j) {
			TM44[i][j - i] = M44[i][j % 4];// 1 2 3 0 <- 0 1 2 3 ..... 3 0 1 2 <- 0 1 2 3
		}
	}

	for (int i = 1; i < 4; ++i) {
		for (int j = 0; j < 4; ++j) {
			M44[i][j] = TM44[i][j];
		}
	}
}

/// <summary>
/// 1 -> 변화 x
/// 2 -> 왼쪽으로 1shift 연산
/// 3 -> 왼쪽으로 1shift 연산후 기존값과 XOR
/// </summary>
int FixedMatrix44[4][4] = {
	{2,3,1,1},
	{1,2,3,1},
	{1,1,2,3},
	{3,1,1,2}
};

void MixColumns() {
	int TM44[4][4] = {}; // 0으로 초기화된 임시행렬
	// 4by4 행렬 곱
	for (int i = 0; i < 4; ++i) {
		for (int j = 0; j < 4; ++j) {
			for (int k = 0; k < 4; ++k) {
				if (FixedMatrix44[j][k] == 1) {
					TM44[j][i] ^= M44[k][i];
				}
				else {
					TM44[j][i] ^= (((M44[k][i] << 1) ^ (((M44[k][i] >> 7) & 1) * 0x1b)));
					if (FixedMatrix44[j][k] == 3) {
						TM44[j][i] ^= M44[k][i];
					}
				}
			}
		}
	}
	
	// 값이 8비트를 넘어갈경우 잘라내기
	for (int i = 0; i < 4; ++i) {
		for (int j = 0; j < 4; ++j) {
			M44[i][j] = TM44[i][j] % 256;
		}
	}
	
}

void InitExpandKey() {
	for (int i = 0; i < 16; ++i) {
		pt_s_str.push_back(plainTxt.substr(i * 2, 2));
		ck_s_str.push_back(cipherKey.substr(i * 2, 2));
	}

	for (int i = 0; i < 16; ++i) {
		v_ptHex16.push_back(stoi(pt_s_str[i], nullptr, 16));
		k_ckHex16.push_back(stoi(ck_s_str[i], nullptr, 16));
	}

	// 행과 열을 교환
	for (int i = 0; i < 4; ++i) {
		for (int j = 0; j < 4; ++j) {
			Key[j][i] = k_ckHex16[i * 4 + j];
		}
	}
}

void ExpandKey() {
	// InitKeyExpand 함수 실행후 실행
	// 이미 4by4 matrix가 존재
	// 동적 계획법(bottom-up) 기법 사용
	for (int i = 4; i < 44; ++i) {
		for (int j = 0; j < 4; ++j) {
			if (i % 4 == 0) {
				// RotWord, S_Box 연산
				for (int k = 0 + 1; k < 4 + 1; ++k) {
					T[k - 1] = S_Box[Key[k % 4][i - 1]];
				}
				if(j==0)
					Key[j][i] = Key[j][i - 4] ^ T[j] ^ rcon[i / 4 - 1];
				else
					Key[j][i] = Key[j][i - 4] ^ T[j];
			}
			else {
				Key[j][i] = Key[j][i - 4] ^ Key[j][i - 1];
			}
		}
	}
}

// AES 알고리즘 10라운드 기준
void AES_Encryption(string str) {
	// INIT
	Init__S_boxMappingTable();

	CreateState(str);
	InitExpandKey();
	ExpandKey();
	AddRoundKey(0);
	for (int i = 1; i < 10; ++i) {
		// cout << "Round" << i << endl;
		SubBytes();
		ShiftRows();
		MixColumns();
		AddRoundKey(i);
	}
	SubBytes();
	ShiftRows();
	AddRoundKey(10);
}

void ECB_Mode(bool isPrint) {
	string tempTxt = plainTxt;
	int size = plainTxt.size();
	for (int i = 0; i < size / 33 + 1; ++i) {
		plainTxt = tempTxt.substr(i * 32, 32);
		int s_size = plainTxt.size();
		// PKCS#7 Padding
		if (s_size < 32) {
			string PKCS7 = "";
			char str[5];
			int hexData = 32 / 2 - s_size / 2;
			sprintf(str, "%02X", hexData);
			PKCS7 = str;
			for (int j = 0; j < hexData; ++j) {
				plainTxt.append(PKCS7);
			}
		}
		AES_Encryption(plainTxt);
		ecb_output_str.push_back( Push_back_Str() );
	}

	if (isPrint) {
		cout << "ECB MODE" << endl;
		int size = ecb_output_str.size();
		for (int i = 0; i < size; ++i) {
			cout << ecb_output_str[i] << " ";
		}
		cout << endl;
	}
}

void CBC_MODE(bool isPrint) {
	string IV = MakeIV();

	// 평문을 16바이트 단위로 잘라내고 PKCS#7 패딩을 적용하는 로직
	string tempTxt = plainTxt;
	int size = plainTxt.size();
	for (int i = 0; i < size / 33 + 1; ++i) {
		plainTxt = tempTxt.substr(i * 32, 32);
		int s_size = plainTxt.size();
		// PKCS#7 Padding
		if (s_size < 32) {
			string PKCS7 = "";
			char str[5];
			int hexData = 32 / 2 - s_size / 2;
			sprintf(str, "%02X", hexData);
			PKCS7 = str;
			for (int j = 0; j < hexData; ++j) {
				plainTxt.append(PKCS7);
			}
		}

		string xorTxt = "";
		for (int j = 0; j < 16; ++j) {
			int subCt;

			if (i == 0) {
				// i가 0이면 초기화 벡터를 사용한다.
				subCt = stoi(IV.substr(j * 2, 2), nullptr, 16);
			}
			else {
				string cipherText = UtilCipherText(false);
				//그 외의 경우에는 cipherText를 사용한다.
				subCt = stoi(cipherText.substr(j * 2, 2), nullptr, 16);
			}
			
			int subPlainText = stoi(plainTxt.substr(j * 2, 2), nullptr, 16);

			char str[5];
			int xorDat = subCt ^ subPlainText;
			sprintf(str, "%02X", xorDat);
			xorTxt.append(str);
		}
		AES_Encryption(xorTxt);
		cbc_output_str.push_back(Push_back_Str());
	}

	if (isPrint) {
		int size = cbc_output_str.size();
		cout << "CBC MODE" << endl;
		for (int i = 0; i < size; ++i) {
			cout << cbc_output_str[i] << " ";
		}
		cout << endl;
	}
}


// 초기화 벡터(IV)를 생성하는 함수
string MakeIV() {
	string ret = "";
	// sprintf 사용을 위한 임시변수
	char str[5];
	for (int i = 0; i < 16; ++i) {
		int rNumber = rand() % 256;
		sprintf(str, "%02X", rNumber);
		ret.append(str);
	}
	return ret;
}

string Push_back_Str() {
	string ret = "";
	for (int i = 0; i < 4; ++i) {
		char str[5]; // 16진수 2자리 + NULL 문자
		for (int j = 0; j < 4; ++j) {
			sprintf(str, "%02X", M44[j][i]);
			ret += str;
		}
	}
	return ret;
}

// 첫번째 인수 - 값을 출력할 것인지?
string UtilCipherText(bool isPrint) {
	ostringstream oss;

	for (int i = 0; i < 4; ++i) {
		for (int j = 0; j < 4; ++j) {
			oss << hex << uppercase << setw(2)<< setfill('0') << M44[j][i];
		}
	}

	if(isPrint)
		cout << oss.str() << endl;

	return oss.str();
}

// 16바이트 16진수 데이터의 string을 4by4 matrix로 변환시키는 연산. 첫번째 인수는 call-by-address 방식을 사용
void Hex16BStringTo4by4Mat(int arr[][4],string value) {
	for (int i = 0; i < 16; ++i) {
		// zero divide error
		if (i == 0) {
			arr[0][0] = stoi(value.substr(0, 2), nullptr, 16);
			continue;
		}
		arr[i%4][i/4] = stoi(value.substr(2 * i, 2),nullptr,16);
	}
}

void CTR_MODE(bool isPrint) {
	// 96비트 nonce 생성
	
	char c_str[9];
	char str[5];
	int counter = 0;// 32비트 카운터

	string tempTxt = plainTxt;
	int size = plainTxt.size();
	for (int i = 0; i < size / 33 + 1; ++i) {
		string substr = "";
		string ret = "";
		// 논스 생성
		for (int j = 0; j < 12; ++j) {
			int rNumber = rand() % 256;
			sprintf(str, "%02X", rNumber);
			ret.append(str);
		}
		// 카운터를 문자열로 변환
		sprintf(c_str, "%08d", counter);
		counter++;
		// 논스와 카운터를 결합
		ret.append(c_str);
		AES_Encryption(ret);

		plainTxt = tempTxt.substr(i * 32, 32);
		int s_size = plainTxt.size();
		// PKCS#7 Padding
		if (s_size < 32) {
			string PKCS7 = "";
			char str[5];
			int hexData = 32 / 2 - s_size / 2;
			sprintf(str, "%02X", hexData);
			PKCS7 = str;
			for (int j = 0; j < hexData; ++j) {
				plainTxt.append(PKCS7);
			}
		}
		ret = UtilCipherText(false);
		// PlainText와 XOR연산
		for (int j = 0; j < 16; ++j) {

			int subCt = stoi(ret.substr(j * 2, 2), nullptr, 16);
			int subPlainText = stoi(plainTxt.substr(j * 2, 2), nullptr, 16);

			char str[5];
			int xorDat = subCt ^ subPlainText;
			sprintf(str, "%02X", xorDat);
			substr.append(str);
		}
		ctr_output_str.push_back(substr);
	}

	if (isPrint) {
		int size = ctr_output_str.size();
		cout << "CTR MODE" << endl;
		for (int i = 0; i < size; ++i) {
			cout << ctr_output_str[i] << " ";
		}
		cout << endl;
	}
}

int main(void) {
	srand(time(NULL));
	
	cout << plainTxt << endl;
	cout << cipherKey << endl;
	plainTxt = "123456789012345678901234567890122234567890123456789012345678901232345678901234567890123456789012";
	cipherKey = "12345678901234567890123456789012";
	CBC_MODE(true);
	plainTxt = "123456789012345678901234567890122234567890123456789012345678901232345678901234567890123456789012";
	cipherKey = "12345678901234567890123456789012";
	CTR_MODE(true);
	plainTxt = "123456789012345678901234567890122234567890123456789012345678901232345678901234567890123456789012";
	cipherKey = "12345678901234567890123456789012";
	ECB_Mode(true);
	return 0;
}