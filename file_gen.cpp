#include <cassert>
//#include <chrono>
#include <iostream>
#include <random>
#include <tfhe++.hpp>

#include <cereal/archives/portable_binary.hpp>
#include <cereal/types/vector.hpp>
#include <fstream>
#include <memory>
#include <filesystem>
#include <vector>
#include "utils.hpp"


using namespace std;

using iksP = TFHEpp::lvl10param;
using bkP = TFHEpp::lvl02param;
using privksP = TFHEpp::lvl21param;

using TLWE_0 = TFHEpp::TLWE<typename bkP::domainP>;
using TLWE_1 = TFHEpp::TLWE<typename privksP::targetP>; // level 1

using TRLWE_1 = TFHEpp::TRLWE<typename privksP::targetP>; // level 1

const double clocks2seconds = 1. / CLOCKS_PER_SEC;
const uint32_t byte_mul2[8] = {0, 0, 0, 0, 0, 0, 0, 0};

//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
static const unsigned char Sbox[16][16] =
  {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  // 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  // 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  // 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  // 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  // 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  // 5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  // 6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  // 7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  // 8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  // 9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  // A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  // B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  // C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  // D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  // E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}; // F


// The round constant word array, Rcon[i], contains the values given by
// x to th e power (i-1) being powers of x (x is denoted as {02}) in the field GF(28)
// Note that i starts at 1, not 0).
int Rcon[255] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb};

long AESKeyExpansion(unsigned char RoundKey[240],
                     unsigned char Key[], int NN)
{
  // Nk is the number of 32-bit works in the AES key (4,6, or 8)
  // Nr is the corresponding number of rounds (10, 12, 14)
  int Nr, Nk = NN / 32;
  switch (NN)
  {
  case 128:
    Nr = 10;
    break;
  case 192:
    Nr = 12;
    break;
  case 256:
    Nr = 14;
    break;
  default:
    printf("Aucune");
    // throw helib::InvalidArgument("Invalid key size: " + std::to_string(NN));
  }
  int i, j;
  unsigned char temp[4], k;
  // The first round key is the key itself.
  for (i = 0; i < Nk; i++)
  {
    RoundKey[i * 4] = Key[i * 4];
    RoundKey[i * 4 + 1] = Key[i * 4 + 1];
    RoundKey[i * 4 + 2] = Key[i * 4 + 2];
    RoundKey[i * 4 + 3] = Key[i * 4 + 3];
  }
  // All other round keys are found from the previous round keys.
  while (i < (Nk * (Nr + 1)))
  {
    for (j = 0; j < 4; j++)
    {
      temp[j] = RoundKey[(i - 1) * 4 + j];
    }
    if (i % Nk == 0)
    {
      // This function rotates the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
            // Function RotWord()
      {
        k = temp[0];
        temp[0] = temp[1];
        temp[1] = temp[2];
        temp[2] = temp[3];
        temp[3] = k;
      }
      // Fonction Subword
      {
        temp[0] = Sbox[temp[0] >> 4][temp[0] & 0x0F];
        temp[1] = Sbox[temp[1] >> 4][temp[1] & 0x0F];
        temp[2] = Sbox[temp[2] >> 4][temp[2] & 0x0F];
        temp[3] = Sbox[temp[3] >> 4][temp[3] & 0x0F];
      }
      temp[0] = temp[0] ^ Rcon[i / Nk];
    }
    else if (Nk > 6 && i % Nk == 4)
    {
      // Fonction Subword
      {
        temp[0] = Sbox[temp[0] >> 4][temp[0] & 0x0F];
        temp[1] = Sbox[temp[1] >> 4][temp[1] & 0x0F];
        temp[2] = Sbox[temp[2] >> 4][temp[2] & 0x0F];
        temp[3] = Sbox[temp[3] >> 4][temp[3] & 0x0F];
      }

    }

    RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ temp[0];
    RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ temp[1];
    RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ temp[2];
    RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ temp[3];
    i++;
  }
  printf("roundkey %x \n" ,RoundKey[17]);
  return Nr + 1;
}
//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

static const unsigned char iSbox[16][16] =
  {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x52 , 0x09 , 0x6a , 0xd5 , 0x30 , 0x36 , 0xa5 , 0x38 , 0xbf , 0x40 , 0xa3 , 0x9e , 0x81 , 0xf3 , 0xd7 , 0xfb ,
    0x7c , 0xe3 , 0x39 , 0x82 , 0x9b , 0x2f , 0xff , 0x87 , 0x34 , 0x8e , 0x43 , 0x44 , 0xc4 , 0xde , 0xe9 , 0xcb ,
    0x54 , 0x7b , 0x94 , 0x32 , 0xa6 , 0xc2 , 0x23 , 0x3d , 0xee , 0x4c , 0x95 , 0x0b , 0x42 , 0xfa , 0xc3 , 0x4e ,
    0x08 , 0x2e , 0xa1 , 0x66 , 0x28 , 0xd9 , 0x24 , 0xb2 , 0x76 , 0x5b , 0xa2 , 0x49 , 0x6d , 0x8b , 0xd1 , 0x25 ,
    0x72 , 0xf8 , 0xf6 , 0x64 , 0x86 , 0x68 , 0x98 , 0x16 , 0xd4 , 0xa4 , 0x5c , 0xcc , 0x5d , 0x65 , 0xb6 , 0x92 ,
    0x6c , 0x70 , 0x48 , 0x50 , 0xfd , 0xed , 0xb9 , 0xda , 0x5e , 0x15 , 0x46 , 0x57 , 0xa7 , 0x8d , 0x9d , 0x84 ,
    0x90 , 0xd8 , 0xab , 0x00 , 0x8c , 0xbc , 0xd3 , 0x0a , 0xf7 , 0xe4 , 0x58 , 0x05 , 0xb8 , 0xb3 , 0x45 , 0x06 ,
    0xd0 , 0x2c , 0x1e , 0x8f , 0xca , 0x3f , 0x0f , 0x02 , 0xc1 , 0xaf , 0xbd , 0x03 , 0x01 , 0x13 , 0x8a , 0x6b ,
    0x3a , 0x91 , 0x11 , 0x41 , 0x4f , 0x67 , 0xdc , 0xea , 0x97 , 0xf2 , 0xcf , 0xce , 0xf0 , 0xb4 , 0xe6 , 0x73 ,
    0x96 , 0xac , 0x74 , 0x22 , 0xe7 , 0xad , 0x35 , 0x85 , 0xe2 , 0xf9 , 0x37 , 0xe8 , 0x1c , 0x75 , 0xdf , 0x6e ,
    0x47 , 0xf1 , 0x1a , 0x71 , 0x1d , 0x29 , 0xc5 , 0x89 , 0x6f , 0xb7 , 0x62 , 0x0e , 0xaa , 0x18 , 0xbe , 0x1b ,
    0xfc , 0x56 , 0x3e , 0x4b , 0xc6 , 0xd2 , 0x79 , 0x20 , 0x9a , 0xdb , 0xc0 , 0xfe , 0x78 , 0xcd , 0x5a , 0xf4 ,
    0x1f , 0xdd , 0xa8 , 0x33 , 0x88 , 0x07 , 0xc7 , 0x31 , 0xb1 , 0x12 , 0x10 , 0x59 , 0x27 , 0x80 , 0xec , 0x5f ,
    0x60 , 0x51 , 0x7f , 0xa9 , 0x19 , 0xb5 , 0x4a , 0x0d , 0x2d , 0xe5 , 0x7a , 0x9f , 0x93 , 0xc9 , 0x9c , 0xef ,
    0xa0 , 0xe0 , 0x3b , 0x4d , 0xae , 0x2a , 0xf5 , 0xb0 , 0xc8 , 0xeb , 0xbb , 0x3c , 0x83 , 0x53 , 0x99 , 0x61 ,
    0x17 , 0x2b , 0x04 , 0x7e , 0xba , 0x77 , 0xd6 , 0x26 , 0xe1 , 0x69 , 0x14 , 0x63 , 0x55 , 0x21 , 0x0c , 0x7d
    };

  // Decryption: Multiply by 9 for InverseMixColumns
  static const unsigned char mul9[16][16] =
  {
    0x00,0x09,0x12,0x1b,0x24,0x2d,0x36,0x3f,0x48,0x41,0x5a,0x53,0x6c,0x65,0x7e,0x77,
    0x90,0x99,0x82,0x8b,0xb4,0xbd,0xa6,0xaf,0xd8,0xd1,0xca,0xc3,0xfc,0xf5,0xee,0xe7,
    0x3b,0x32,0x29,0x20,0x1f,0x16,0x0d,0x04,0x73,0x7a,0x61,0x68,0x57,0x5e,0x45,0x4c,
    0xab,0xa2,0xb9,0xb0,0x8f,0x86,0x9d,0x94,0xe3,0xea,0xf1,0xf8,0xc7,0xce,0xd5,0xdc,
    0x76,0x7f,0x64,0x6d,0x52,0x5b,0x40,0x49,0x3e,0x37,0x2c,0x25,0x1a,0x13,0x08,0x01,
    0xe6,0xef,0xf4,0xfd,0xc2,0xcb,0xd0,0xd9,0xae,0xa7,0xbc,0xb5,0x8a,0x83,0x98,0x91,
    0x4d,0x44,0x5f,0x56,0x69,0x60,0x7b,0x72,0x05,0x0c,0x17,0x1e,0x21,0x28,0x33,0x3a,
    0xdd,0xd4,0xcf,0xc6,0xf9,0xf0,0xeb,0xe2,0x95,0x9c,0x87,0x8e,0xb1,0xb8,0xa3,0xaa,
    0xec,0xe5,0xfe,0xf7,0xc8,0xc1,0xda,0xd3,0xa4,0xad,0xb6,0xbf,0x80,0x89,0x92,0x9b,
    0x7c,0x75,0x6e,0x67,0x58,0x51,0x4a,0x43,0x34,0x3d,0x26,0x2f,0x10,0x19,0x02,0x0b,
    0xd7,0xde,0xc5,0xcc,0xf3,0xfa,0xe1,0xe8,0x9f,0x96,0x8d,0x84,0xbb,0xb2,0xa9,0xa0,
    0x47,0x4e,0x55,0x5c,0x63,0x6a,0x71,0x78,0x0f,0x06,0x1d,0x14,0x2b,0x22,0x39,0x30,
    0x9a,0x93,0x88,0x81,0xbe,0xb7,0xac,0xa5,0xd2,0xdb,0xc0,0xc9,0xf6,0xff,0xe4,0xed,
    0x0a,0x03,0x18,0x11,0x2e,0x27,0x3c,0x35,0x42,0x4b,0x50,0x59,0x66,0x6f,0x74,0x7d,
    0xa1,0xa8,0xb3,0xba,0x85,0x8c,0x97,0x9e,0xe9,0xe0,0xfb,0xf2,0xcd,0xc4,0xdf,0xd6,
    0x31,0x38,0x23,0x2a,0x15,0x1c,0x07,0x0e,0x79,0x70,0x6b,0x62,0x5d,0x54,0x4f,0x46
  };

  // Decryption: Multiply by 11 for InverseMixColumns
  static const unsigned char mul11[16][16] =
  {
    0x00,0x0b,0x16,0x1d,0x2c,0x27,0x3a,0x31,0x58,0x53,0x4e,0x45,0x74,0x7f,0x62,0x69,
    0xb0,0xbb,0xa6,0xad,0x9c,0x97,0x8a,0x81,0xe8,0xe3,0xfe,0xf5,0xc4,0xcf,0xd2,0xd9,
    0x7b,0x70,0x6d,0x66,0x57,0x5c,0x41,0x4a,0x23,0x28,0x35,0x3e,0x0f,0x04,0x19,0x12,
    0xcb,0xc0,0xdd,0xd6,0xe7,0xec,0xf1,0xfa,0x93,0x98,0x85,0x8e,0xbf,0xb4,0xa9,0xa2,
    0xf6,0xfd,0xe0,0xeb,0xda,0xd1,0xcc,0xc7,0xae,0xa5,0xb8,0xb3,0x82,0x89,0x94,0x9f,
    0x46,0x4d,0x50,0x5b,0x6a,0x61,0x7c,0x77,0x1e,0x15,0x08,0x03,0x32,0x39,0x24,0x2f,
    0x8d,0x86,0x9b,0x90,0xa1,0xaa,0xb7,0xbc,0xd5,0xde,0xc3,0xc8,0xf9,0xf2,0xef,0xe4,
    0x3d,0x36,0x2b,0x20,0x11,0x1a,0x07,0x0c,0x65,0x6e,0x73,0x78,0x49,0x42,0x5f,0x54,
    0xf7,0xfc,0xe1,0xea,0xdb,0xd0,0xcd,0xc6,0xaf,0xa4,0xb9,0xb2,0x83,0x88,0x95,0x9e,
    0x47,0x4c,0x51,0x5a,0x6b,0x60,0x7d,0x76,0x1f,0x14,0x09,0x02,0x33,0x38,0x25,0x2e,
    0x8c,0x87,0x9a,0x91,0xa0,0xab,0xb6,0xbd,0xd4,0xdf,0xc2,0xc9,0xf8,0xf3,0xee,0xe5,
    0x3c,0x37,0x2a,0x21,0x10,0x1b,0x06,0x0d,0x64,0x6f,0x72,0x79,0x48,0x43,0x5e,0x55,
    0x01,0x0a,0x17,0x1c,0x2d,0x26,0x3b,0x30,0x59,0x52,0x4f,0x44,0x75,0x7e,0x63,0x68,
    0xb1,0xba,0xa7,0xac,0x9d,0x96,0x8b,0x80,0xe9,0xe2,0xff,0xf4,0xc5,0xce,0xd3,0xd8,
    0x7a,0x71,0x6c,0x67,0x56,0x5d,0x40,0x4b,0x22,0x29,0x34,0x3f,0x0e,0x05,0x18,0x13,
    0xca,0xc1,0xdc,0xd7,0xe6,0xed,0xf0,0xfb,0x92,0x99,0x84,0x8f,0xbe,0xb5,0xa8,0xa3
  };

  // Decryption: Multiply by 13 for InverseMixColumns
  static const unsigned char mul13[16][16] =
  {
    0x00,0x0d,0x1a,0x17,0x34,0x39,0x2e,0x23,0x68,0x65,0x72,0x7f,0x5c,0x51,0x46,0x4b,
    0xd0,0xdd,0xca,0xc7,0xe4,0xe9,0xfe,0xf3,0xb8,0xb5,0xa2,0xaf,0x8c,0x81,0x96,0x9b,
    0xbb,0xb6,0xa1,0xac,0x8f,0x82,0x95,0x98,0xd3,0xde,0xc9,0xc4,0xe7,0xea,0xfd,0xf0,
    0x6b,0x66,0x71,0x7c,0x5f,0x52,0x45,0x48,0x03,0x0e,0x19,0x14,0x37,0x3a,0x2d,0x20,
    0x6d,0x60,0x77,0x7a,0x59,0x54,0x43,0x4e,0x05,0x08,0x1f,0x12,0x31,0x3c,0x2b,0x26,
    0xbd,0xb0,0xa7,0xaa,0x89,0x84,0x93,0x9e,0xd5,0xd8,0xcf,0xc2,0xe1,0xec,0xfb,0xf6,
    0xd6,0xdb,0xcc,0xc1,0xe2,0xef,0xf8,0xf5,0xbe,0xb3,0xa4,0xa9,0x8a,0x87,0x90,0x9d,
    0x06,0x0b,0x1c,0x11,0x32,0x3f,0x28,0x25,0x6e,0x63,0x74,0x79,0x5a,0x57,0x40,0x4d,
    0xda,0xd7,0xc0,0xcd,0xee,0xe3,0xf4,0xf9,0xb2,0xbf,0xa8,0xa5,0x86,0x8b,0x9c,0x91,
    0x0a,0x07,0x10,0x1d,0x3e,0x33,0x24,0x29,0x62,0x6f,0x78,0x75,0x56,0x5b,0x4c,0x41,
    0x61,0x6c,0x7b,0x76,0x55,0x58,0x4f,0x42,0x09,0x04,0x13,0x1e,0x3d,0x30,0x27,0x2a,
    0xb1,0xbc,0xab,0xa6,0x85,0x88,0x9f,0x92,0xd9,0xd4,0xc3,0xce,0xed,0xe0,0xf7,0xfa,
    0xb7,0xba,0xad,0xa0,0x83,0x8e,0x99,0x94,0xdf,0xd2,0xc5,0xc8,0xeb,0xe6,0xf1,0xfc,
    0x67,0x6a,0x7d,0x70,0x53,0x5e,0x49,0x44,0x0f,0x02,0x15,0x18,0x3b,0x36,0x21,0x2c,
    0x0c,0x01,0x16,0x1b,0x38,0x35,0x22,0x2f,0x64,0x69,0x7e,0x73,0x50,0x5d,0x4a,0x47,
    0xdc,0xd1,0xc6,0xcb,0xe8,0xe5,0xf2,0xff,0xb4,0xb9,0xae,0xa3,0x80,0x8d,0x9a,0x97
  };

  // Decryption: Multiply by 14 for InverseMixColumns
  static const unsigned char mul14[16][16] =
  {
    0x00,0x0e,0x1c,0x12,0x38,0x36,0x24,0x2a,0x70,0x7e,0x6c,0x62,0x48,0x46,0x54,0x5a,
    0xe0,0xee,0xfc,0xf2,0xd8,0xd6,0xc4,0xca,0x90,0x9e,0x8c,0x82,0xa8,0xa6,0xb4,0xba,
    0xdb,0xd5,0xc7,0xc9,0xe3,0xed,0xff,0xf1,0xab,0xa5,0xb7,0xb9,0x93,0x9d,0x8f,0x81,
    0x3b,0x35,0x27,0x29,0x03,0x0d,0x1f,0x11,0x4b,0x45,0x57,0x59,0x73,0x7d,0x6f,0x61,
    0xad,0xa3,0xb1,0xbf,0x95,0x9b,0x89,0x87,0xdd,0xd3,0xc1,0xcf,0xe5,0xeb,0xf9,0xf7,
    0x4d,0x43,0x51,0x5f,0x75,0x7b,0x69,0x67,0x3d,0x33,0x21,0x2f,0x05,0x0b,0x19,0x17,
    0x76,0x78,0x6a,0x64,0x4e,0x40,0x52,0x5c,0x06,0x08,0x1a,0x14,0x3e,0x30,0x22,0x2c,
    0x96,0x98,0x8a,0x84,0xae,0xa0,0xb2,0xbc,0xe6,0xe8,0xfa,0xf4,0xde,0xd0,0xc2,0xcc,
    0x41,0x4f,0x5d,0x53,0x79,0x77,0x65,0x6b,0x31,0x3f,0x2d,0x23,0x09,0x07,0x15,0x1b,
    0xa1,0xaf,0xbd,0xb3,0x99,0x97,0x85,0x8b,0xd1,0xdf,0xcd,0xc3,0xe9,0xe7,0xf5,0xfb,
    0x9a,0x94,0x86,0x88,0xa2,0xac,0xbe,0xb0,0xea,0xe4,0xf6,0xf8,0xd2,0xdc,0xce,0xc0,
    0x7a,0x74,0x66,0x68,0x42,0x4c,0x5e,0x50,0x0a,0x04,0x16,0x18,0x32,0x3c,0x2e,0x20,
    0xec,0xe2,0xf0,0xfe,0xd4,0xda,0xc8,0xc6,0x9c,0x92,0x80,0x8e,0xa4,0xaa,0xb8,0xb6,
    0x0c,0x02,0x10,0x1e,0x34,0x3a,0x28,0x26,0x7c,0x72,0x60,0x6e,0x44,0x4a,0x58,0x56,
    0x37,0x39,0x2b,0x25,0x0f,0x01,0x13,0x1d,0x47,0x49,0x5b,0x55,0x7f,0x71,0x63,0x6d,
    0xd7,0xd9,0xcb,0xc5,0xef,0xe1,0xf3,0xfd,0xa7,0xa9,0xbb,0xb5,0x9f,0x91,0x83,0x8d
  };

void MakeTable(std::vector<TRLWE_1> &Table, const TFHEpp::Key<privksP::targetP> &key, const unsigned char source[16][16]) {
  // Tableau binaire pour la conversion
  int binary[256][8];

  // Remplissage du tableau binaire à partir de la source
  for (int i = 0; i < 16; i++) {
    for (int j = 0; j < 16; j++) {
      int bin_str[8];
      HexToBinStr(source[i][j], bin_str); // Conversion de l'hexadécimal en binaire
      for (int k = 0; k < 8; k++) {
        binary[i * 16 + j][k] = bin_str[k];
      }
    }
  }

  // mixpacking et chiffrement
  for (int k = 0; k < 2; k++) {
    TFHEpp::Polynomial<typename privksP::targetP> poly;
    for (int i = 0; i < 128; i++) {
      for (int j = 0; j < 8; j++) {
        poly[i * 8 + j] = (typename privksP::targetP::T)binary[k * 128 + i][j];
      }
    }
    Table[k] = TFHEpp::trlweSymIntEncrypt<privksP::targetP>(poly, privksP::targetP::alpha, key);
  }
}

void file_gen()
{
  std::random_device seed_gen;
  std::default_random_engine engine(seed_gen());
  std::uniform_int_distribution<uint32_t> binary(0, 1);

  // Generate key
  /////////////////////TFHEpp::SecretKey *sk = new TFHEpp::SecretKey;
  unique_ptr<TFHEpp::SecretKey> sk = make_unique<TFHEpp::SecretKey>();
  TFHEpp::EvalKey ek;
  ek.emplaceiksk<iksP>(*sk);
  ek.emplacebkfft<bkP>(*sk);
  ek.emplaceprivksk4cb<privksP>(*sk);
  ek.emplacebkfft<TFHEpp::lvl01param>(*sk); // used for identitybootstrapping

  std::filesystem::create_directories("../homoData");
  // export the secret key to file for later use
  {
    std::ofstream ofs{"../homoData/sk.key", std::ios::binary};
    cereal::PortableBinaryOutputArchive ar(ofs);
    sk->serialize(ar);
    std::cout << "The SecretKey has been serialized." << std::endl;
  };

  // export the cloud key to a file (for the cloud)
  {
    std::ofstream ofs{"../homoData/ek.key", std::ios::binary};
    cereal::PortableBinaryOutputArchive ar(ofs);
    ek.serialize(ar);
    std::cout << "The cloud key ek has been serialized." << std::endl;
  };

//=========================================================================================
  int i, Nr=0, Nk=0, NN=128;
  unsigned char ka[16], kb[16], plain[16], RoundKeya[240], RoundKeyb[240];

  // Calculate Nk and Nr from the received value.
  Nk = NN / 32;  //4
  Nr = Nk + 6;   //10

  printf("Entrez le message chiffré en hexadécimal : ");
  for(i=0; i<16; i++)
  {
  scanf("%0hhx",&plain[i]);
  }

    printf("Entrez la clé Alice ka en hexadécimal : ");
  for(i=0; i<16; i++)
  {
  scanf("%0hhx",&ka[i]);
  }
  printf("Entrez la clé Bob kb en hexadécimal :  ");
  for(i=0; i<16; i++)
  {
  scanf("%0hhx",&kb[i]);
  }

  cout << " .........RoundKey........" << endl;
  // Compute the key expansion
  //unsigned char RoundKey[240];
  long kaRoundKeys = AESKeyExpansion(RoundKeya, ka, 128);
  long kbRoundKeys = AESKeyExpansion(RoundKeyb, kb, 128);
  cout << " rounds ka: " << kaRoundKeys << endl;
  cout << " rounds kb: " << kbRoundKeys << endl;

  std::vector<std::vector<TLWE_0>> rka, rkb;
  rka.resize(240), rkb.resize(240);
  for (int i = 0; i < 240; i++)
  {
    int bin_ka[8], bin_kb[8];
    rka[i].resize(8), rkb[i].resize(8);
    HexToBinStr(RoundKeya[i], bin_ka);
    HexToBinStr(RoundKeyb[i], bin_kb);
    for (int j = 0; j < 8; j++)
    {
      rka[i][j] = TFHEpp::tlweSymIntEncrypt<typename bkP::domainP>((typename bkP::domainP::T)bin_ka[j], bkP::domainP::alpha,
                                                                    sk->key.get<typename bkP::domainP>());
      rkb[i][j] = TFHEpp::tlweSymIntEncrypt<typename bkP::domainP>((typename bkP::domainP::T)bin_kb[j], bkP::domainP::alpha,
                                                                    sk->key.get<typename bkP::domainP>());
    }
  }

  std::vector<std::vector<TLWE_0>> cipher;
  cipher.resize(16);
  for (int i = 0; i < 16; i++)
  {
    cipher[i].resize(8);
  }
  for (int i = 0; i < 16; i++)
  {
    int bin_str[8];
    HexToBinStr(plain[i], bin_str);
    for (int j = 0; j < 8; j++)
    {
      cipher[i][j] = TFHEpp::tlweSymIntEncrypt<typename bkP::domainP>((typename bkP::domainP::T)bin_str[j], bkP::domainP::alpha,
                                                                      sk->key.get<typename bkP::domainP>());
    }
  }
  std::vector<TLWE_0> consByte(8);
  for (int i = 0; i < 8; i++)
  {
    // encrypt 0
    consByte[i] = TFHEpp::tlweSymIntEncrypt<typename bkP::domainP>((typename bkP::domainP::T)byte_mul2[i], bkP::domainP::alpha,
                                                                    sk->key.get<typename bkP::domainP>());
  }
  // export the round_keys key to a file (for the round_keys)
  {
    std::ofstream ofs{"../homoData/ka.key", std::ios::binary};
    cereal::PortableBinaryOutputArchive ar(ofs);
    ar(rka);
    std::cout << "The ka key has been serialized." << std::endl;
  };
  {
    std::ofstream ofs{"../homoData/kb.key", std::ios::binary};
    cereal::PortableBinaryOutputArchive ar(ofs);
    ar(rkb);
    std::cout << "The kb key has been serialized." << std::endl;
  };
  {
    std::ofstream ofs{"../homoData/ciphertext.data", std::ios::binary};
    cereal::PortableBinaryOutputArchive ar(ofs);
    ar(cipher);
    std::cout << "The ciphertext has been serialized." << std::endl;
  };
  {
    std::ofstream ofs{"../homoData/consByte.data", std::ios::binary};
    cereal::PortableBinaryOutputArchive ar(ofs);
    ar(consByte);
    std::cout << "The consByte has been serialized." << std::endl;
  };

  std::cout << " ==================  MakeTable=================" << endl;
  std::vector<TRLWE_1> Table(2), iTable(2), Table9(2), Table11(2), Table13(2), Table14(2) ;
  MakeTable(Table, sk->key.get<privksP::targetP>(), Sbox); // Utiliser la clé TRLWE de niveau 1
  MakeTable(iTable, sk->key.get<privksP::targetP>(), iSbox); //Utiliser la clé TRLWE de niveau 1
  MakeTable(Table9, sk->key.get<privksP::targetP>(), mul9);
  MakeTable(Table11, sk->key.get<privksP::targetP>(), mul11);
  MakeTable(Table13, sk->key.get<privksP::targetP>(), mul13);
  MakeTable(Table14, sk->key.get<privksP::targetP>(), mul14);
  {
    std::ofstream ofs{"../homoData/Sbox.data", std::ios::binary};
    cereal::PortableBinaryOutputArchive ar(ofs);
    ar(Table);
    std::cout << "The Sbox  has been serialized." << std::endl;
  };
  {
    std::ofstream ofs{"../homoData/iSbox.data", std::ios::binary};
    cereal::PortableBinaryOutputArchive ar(ofs);
    ar(iTable);
    std::cout << "The iSbox  has been serialized." << std::endl;
  };
  {
    std::ofstream ofs{"../homoData/mul9.data", std::ios::binary};
    cereal::PortableBinaryOutputArchive ar(ofs);
    ar(Table9);
    std::cout << "The mul9  has been serialized." << std::endl;
  };
  {
    std::ofstream ofs{"../homoData/mul11.data", std::ios::binary};
    cereal::PortableBinaryOutputArchive ar(ofs);
    ar(Table11);
    std::cout << "The mul11  has been serialized." << std::endl;
  };
  {
    std::ofstream ofs{"../homoData/mul13.data", std::ios::binary};
    cereal::PortableBinaryOutputArchive ar(ofs);
    ar(Table13);
    std::cout << "The mul13  has been serialized." << std::endl;
  };
  {
    std::ofstream ofs{"../homoData/mul14.data", std::ios::binary};
    cereal::PortableBinaryOutputArchive ar(ofs);
    ar(Table14);
    std::cout << "The mul14  has been serialized." << std::endl;
  };
    cout << endl;


}
