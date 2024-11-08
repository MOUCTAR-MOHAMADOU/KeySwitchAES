#include <cassert>
#include <chrono>
#include <iostream>
#include <random>
#include <tfhe++.hpp>

#include <fstream>
#include <memory>
#include <vector>
#include <cereal/archives/portable_binary.hpp>
#include <cereal/types/vector.hpp>
#include "utils.hpp"

using namespace std;

using iksP = TFHEpp::lvl10param;
using bkP = TFHEpp::lvl02param;
using privksP = TFHEpp::lvl21param;

using TLWE_0 = TFHEpp::TLWE<typename bkP::domainP>;
using TLWE_1 = TFHEpp::TLWE<typename privksP::targetP>; // level 1

using TRLWE_1 = TFHEpp::TRLWE<typename privksP::targetP>; // level 1


template <class P>
void XOR_Two(P &result, P &a, P &b)
{
    for (int i = 0; i < 8; i++)
    {
        for (int num = 0; num < bkP::domainP::n + 1; num++)
        {
            result[i][num] = a[i][num] + b[i][num];
        }
        // cout<<endl;
    }
}

template <class P>
void XOR_Four(P &result, P &a, P &b, P &c, P &d)
{
    XOR_Two<P>(result, a, b);
    XOR_Two<P>(result, result, c);
    XOR_Two<P>(result, result, d);
}


void CipherAddRoundKey(std::vector<std::vector<TLWE_0>> &cipher, std::vector<std::vector<TLWE_0>> &rk, int round)
{
    for (int i = 0; i < 16; i++)
    {
        XOR_Two(cipher[i], cipher[i], rk[round * 16 + i]);
    }
}

void CipherShiftRows(std::vector<std::vector<TLWE_0>> &cipher, std::vector<std::vector<TLWE_0>> &B)
{
    //  0  4  8  12                 \    0  4  8  12
    //  1  5  9  13           =======\   5  9  13 1
    //  2  6  10 14           ======-/   10 14 2  6
    //  3  7  11 15                 /    15 3  7  11

    for (int j = 0; j < 8; j++)
    {
        for (int i = 0; i < 16; i++)
        {
            TFHEpp::HomCOPY<typename bkP::domainP>(cipher[i][j], B[(5 * i) % 16][j]);
        }
    }
}

void CipheriShiftRows(std::vector<std::vector<TLWE_0>> &cipher, std::vector<std::vector<TLWE_0>> &B) {
      for (int i = 0; i < 8; i++)
     {
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[0][i], B[0][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[1][i], B[13][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[2][i], B[10][i]);         
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[3][i], B[7][i]);

         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[4][i], B[4][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[5][i], B[1][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[6][i], B[14][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[7][i], B[11][i]);

         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[8][i], B[8][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[9][i], B[5][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[10][i], B[2][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[11][i], B[15][i]);

         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[12][i], B[12][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[13][i], B[9][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[14][i], B[6][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[15][i], B[3][i]);
     }
}

void MixedPacking(TRLWE_1 &result, vector<TRLWE_1> &Table, vector<TFHEpp::TRGSWFFT<typename privksP::targetP>> &select) {
    // Utilisation de CMUXFFT
    TFHEpp::CMUXFFT<typename privksP::targetP>(result, select[7], Table[1], Table[0]);

    // Création du tableau pour BlindRotate_LUT
    privksP::targetP::T *bara = new privksP::targetP::T[8];
    privksP::targetP::T NX2 = 2 * privksP::targetP::n;

    // Remplissage du tableau bara
    for (int32_t i = 0; i < 7; i++) {
        bara[i] = NX2 - 8 * pow(2, i);
    }

    // Appel à BlindRotate_LUT
    TFHEpp::BlindRotate_LUT<privksP>(result, bara, select, 7);

    // Libération de la mémoire
    //delete[] bara;
}

void CipherMul2(std::vector<TLWE_0> &byte, std::vector<TLWE_0> &consByte)
{
    // byte((b7 b6 b5 b4 b3 b2 b1)*x = b6 b5 b4 b3 b2 b1 b0 b7 + 000b7 b70 b7 0
    // consByte = 0000 0000
    std::vector<TLWE_0> temp(8);

    for (int i = 1; i < 8; i++)
    {
        TFHEpp::HomCOPY<typename bkP::domainP>(temp[i], byte[i - 1]);
    }
    TFHEpp::HomCOPY<typename bkP::domainP>(temp[0], byte[7]);

    for (int i = 0; i < 8; i++)
    {
        if (i == 1 || i == 3 || i == 4)
        {
            // 000b7 b70 b7 0
            TFHEpp::HomCOPY<typename bkP::domainP>(consByte[i], byte[7]);
        }
    }
    XOR_Two(byte, temp, consByte);
}

void CipherMixColumns(std::vector<std::vector<TLWE_0>> &cipher, std::vector<TLWE_0> &consByte)
{
    // cout << "==============CipherMixColumns==============" << endl;
    //
    // [02  03  01  01] [ s00  s01  s02  s03]
    // |01  02  03  01| | s10  s11  s12  s13|
    // |01  01  02  03| | s20  s21  s22  s23|
    // [03  01  01  02] [ s30  s31  s32  s33]
    //

    for (int i = 0; i < 4; i++)
    {
        std::vector<TLWE_0> t(8);
        std::vector<TLWE_0> Tmp(8);
        std::vector<TLWE_0> Tm(8);

        for (int j = 0; j < 8; j++)
        {
            TFHEpp::HomCOPY<typename bkP::domainP>(t[j], cipher[4 * i + 0][j]);
        }
        // Tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i]; 
        XOR_Four(Tmp, cipher[4 * i + 0], cipher[4 * i + 1], cipher[4 * i + 2], cipher[4 * i + 3]);

        // Tm = state[0][i] ^ state[1][i];
        for (int j = 0; j < 8; j++)
        {
            TFHEpp::HomCOPY<typename bkP::domainP>(Tm[j], cipher[4 * i + 0][j]); // t = cipher[0][i]
        }
        XOR_Two(Tm, Tm, cipher[4 * i + 1]);

        // Tm = xtime(Tm)   // 6b->d6
        CipherMul2(Tm, consByte);

        // state[0][i] ^= Tm ^ Tmp;
        XOR_Two(cipher[4 * i + 0], cipher[4 * i + 0], Tm);  // 2
        XOR_Two(cipher[4 * i + 0], cipher[4 * i + 0], Tmp); // 4

        //======================================================
        //  Tm = state[1][i] ^ state[2][i];
        for (int j = 0; j < 8; j++)
        {
            TFHEpp::HomCOPY<typename bkP::domainP>(Tm[j], cipher[4 * i + 1][j]);
        }
        XOR_Two(Tm, Tm, cipher[4 * i + 2]);
        //  Tm = xtime(Tm);
        CipherMul2(Tm, consByte);
        // state[1][i] ^= Tm ^ Tmp;
        XOR_Two(cipher[4 * i + 1], cipher[4 * i + 1], Tm);
        XOR_Two(cipher[4 * i + 1], cipher[4 * i + 1], Tmp);

        //======================================================
        // Tm = state[2][i] ^ state[3][i];
        for (int j = 0; j < 8; j++)
        {
            TFHEpp::HomCOPY<typename bkP::domainP>(Tm[j], cipher[4 * i + 2][j]);
        }
        XOR_Two(Tm, Tm, cipher[4 * i + 3]);
        // Tm = xtime(Tm);
        CipherMul2(Tm, consByte);
        // state[2][i] ^= Tm ^ Tmp;
        XOR_Two(cipher[4 * i + 2], cipher[4 * i + 2], Tm);
        XOR_Two(cipher[4 * i + 2], cipher[4 * i + 2], Tmp);

        //======================================================
        // Tm = state[3][i] ^ t;
        for (int j = 0; j < 8; j++)
        {
            TFHEpp::HomCOPY<typename bkP::domainP>(Tm[j], cipher[4 * i + 3][j]);
        }
        XOR_Two(Tm, Tm, t);

        // Tm = xtime(Tm);
        CipherMul2(Tm, consByte);
        // state[3][i] ^= Tm ^ Tmp;
        XOR_Two(cipher[4 * i + 3], cipher[4 * i + 3], Tm);
        XOR_Two(cipher[4 * i + 3], cipher[4 * i + 3], Tmp);
    }
}


void k_switch()
{
  TFHEpp::EvalKey ek;
  {
    ifstream ifs("../homoData/ek.key", ios::binary);
    cereal::PortableBinaryInputArchive ar(ifs);
    ek.serialize(ar);
    cout << "cloud a été désérialisé." << endl;
  }
  vector<vector<TLWE_0>> cipher, rka;  
  {
    ifstream ifs{"../homoData/ciphertext.data", ios::binary};
    cereal::PortableBinaryInputArchive ar(ifs);
    ar(cipher);
    cout << "ciphertext a été désérialisé." << endl;
  }  
  std::cout << " ================== MakeTable =================" << endl;
  vector<TRLWE_1> iTable(2), Table9(2), Table11(2), Table13(2), Table14(2);
  {
    ifstream ifs{"../homoData/iSbox.data", ios::binary};
    cereal::PortableBinaryInputArchive ar(ifs);
    ar(iTable);
    cout << "iSbox.data a été désérialisé." << endl;
  }
  {
    ifstream ifs{"../homoData/mul9.data", ios::binary};
    cereal::PortableBinaryInputArchive ar(ifs);
    ar(Table9);
    cout << "mul9.data a été désérialisé." << endl;
  }
  {
    ifstream ifs{"../homoData/mul11.data", ios::binary};
    cereal::PortableBinaryInputArchive ar(ifs);
    ar(Table11);
    cout << "mul11.data a été désérialisé." << endl;
  }
  {
    ifstream ifs{"../homoData/mul13.data", ios::binary};
    cereal::PortableBinaryInputArchive ar(ifs);
    ar(Table13);
    cout << "mul13.data a été désérialisé." << endl;
  }
  {
    ifstream ifs{"../homoData/mul14.data", ios::binary};
    cereal::PortableBinaryInputArchive ar(ifs);
    ar(Table14);
    cout << "mul14.data a été désérialisé." << endl;
  }
  {
    ifstream ifs{"../homoData/ka.key", ios::binary};
    cereal::PortableBinaryInputArchive ar(ifs);
    ar(rka);
    cout << "ka a été désérialisé." << endl;
  }  

//          ******************************************************** 

  chrono::system_clock::time_point start, end;
  double cb_totaltime = 0, lut_totaltime = 0, Idks_totaltime = 0, 
        icb_totaltime = 0, ilut_totaltime = 0, iIdks_totaltime = 0;
  start = chrono::system_clock::now();

  chrono::system_clock::time_point dec_start, dec_end;
  dec_start = chrono::system_clock::now();

/////////////////////////////// CipherAddRoundKey

        CipherAddRoundKey(cipher, rka, 10);

///////////////////////////////There will begin 9 rounds//////////////////////////////
  vector<vector<TFHEpp::TRGSWFFT<typename privksP::targetP>>> bootedTGSW;
  bootedTGSW.resize(16);
  for (int i = 0; i < 16; i++)
  {
    bootedTGSW[i].resize(8);
  }
  vector<TRLWE_1> lut_iresult(16);   
  for (int i = 1; i < 10; i++)
{
      cout << "================ Invere round: " << i << "==================" << endl;
  int r = 10-i;
  vector<vector<TLWE_0>> B;
  B.resize(16);
  for (int i = 0; i < 16; i++)
  {
    B[i].resize(8);
  }
  for (int i = 0; i < 16; i++)
  {
    for (int j = 0; j < 8; j++)
    {
      B[i][j] = cipher[i][j];
    }
  }    

/////////////////////////////// CipheriShiftRows

    CipheriShiftRows(cipher, B);

  chrono::system_clock::time_point icb_start, icb_end;
  icb_start = chrono::system_clock::now();

  for (int i = 0; i < 16; i++)
  {
    for (int j = 0; j < 8; j++)
    {
      TFHEpp::SM4_CircuitBootstrappingFFT<iksP, bkP, privksP>(bootedTGSW[i][j], cipher[i][j], ek);
    }
  }
  
  icb_end = chrono::system_clock::now();
  double icb_elapsed = chrono::duration_cast<chrono::milliseconds>(icb_end - icb_start).count();
  cout << " Inverse Circuit bootstrapping(16 * 8 times) one round costs: " << icb_elapsed << "ms" << endl;
  icb_totaltime += icb_elapsed;

  chrono::system_clock::time_point ilut_start, ilut_end;
  ilut_start = chrono::system_clock::now();
  
  for (int i = 0; i < 16; i++)
  {
    MixedPacking(lut_iresult[i], iTable, bootedTGSW[i]);
  }

  ilut_end = chrono::system_clock::now();
  double ilut_elapsed = chrono::duration_cast<chrono::microseconds>(ilut_end - ilut_start).count();
  cout << " iSbox lookup table one round costs: " << ilut_elapsed << "us" << endl;
  ilut_totaltime += ilut_elapsed;

  vector<vector<TLWE_1>> iSbox_value;
  iSbox_value.resize(16);
  for (int i = 0; i < iSbox_value.size(); i++)
  {
    iSbox_value[i].resize(8);
  }
  // SampleExtract level 1
  for (int i = 0; i < 16; i++)
  {
    for (int j = 0; j < 8; j++)
    {
      TFHEpp::SampleExtractIndex<typename privksP::targetP>(iSbox_value[i][j], lut_iresult[i], j);
    }
  }

  chrono::system_clock::time_point iks_start, iks_end;
  iks_start = chrono::system_clock::now();

/////////////////////////////// CipheriSubBytes

  for (int i = 0; i < 16; i++)
  {
    for (int j = 0; j < 8; j++)
    {
    // level 1 -> level 0
    TFHEpp::IdentityKeySwitch<iksP>(B[i][j], iSbox_value[i][j], ek.getiksk<iksP>());
    }
  }

  iks_end = chrono::system_clock::now();
  double iks_elapsed = chrono::duration_cast<chrono::milliseconds>(iks_end - iks_start).count();
  cout << "Inverse Identity keyswitch(16 * 8 times) one round costs: " << iks_elapsed << "ms" << endl;
  iIdks_totaltime += iks_elapsed;

/////////////////////////////// CipherAddRoundKey      

    CipherAddRoundKey(B, rka, r);        


  chrono::system_clock::time_point incb_start, incb_end;
  incb_start = chrono::system_clock::now();             

  for (int i = 0; i < 16; i++)
  {
    for (int j = 0; j < 8; j++)  {
      TFHEpp::SM4_CircuitBootstrappingFFT<iksP, bkP, privksP>(bootedTGSW[i][j], B[i][j], ek);
    }
  }

  incb_end = chrono::system_clock::now();
  double incb_elapsed = chrono::duration_cast<chrono::milliseconds>(incb_end - incb_start).count();
  cout << " Mult Circuit bootstrapping(16 * 8 times) one round costs: " << incb_elapsed << "ms" << endl;
  icb_totaltime += incb_elapsed;

  vector<TRLWE_1> lut_result9(16), lut_result11(16), lut_result13(16), lut_result14(16); 
  chrono::system_clock::time_point inlut_start, inlut_end;
  inlut_start = chrono::system_clock::now();

  for (int i = 0; i < 16; i++)
  {
    MixedPacking(lut_result9[i], Table9, bootedTGSW[i]);
    MixedPacking(lut_result11[i], Table11, bootedTGSW[i]);
    MixedPacking(lut_result13[i], Table13, bootedTGSW[i]);
    MixedPacking(lut_result14[i], Table14, bootedTGSW[i]);
  }

  inlut_end = chrono::system_clock::now();
  double inlut_elapsed = chrono::duration_cast<chrono::microseconds>(inlut_end - inlut_start).count();
  cout << " Mult lookup table one round costs: " << inlut_elapsed << "us" << endl;
  ilut_totaltime += inlut_elapsed;
  
  vector<vector<TLWE_1>> mul9_value, mul11_value, mul13_value, mul14_value;
  vector<vector<TLWE_0>> mul9, mul11, mul13, mul14;
  mul9_value.resize(16);  mul11_value.resize(16); mul13_value.resize(16); mul14_value.resize(16);
  mul9.resize(16); mul11.resize(16); mul13.resize(16); mul14.resize(16);
  for (int i = 0; i < 16; i++)
  {
    mul9_value[i].resize(8); mul11_value[i].resize(8);
    mul13_value[i].resize(8); mul14_value[i].resize(8);
    mul9[i].resize(8);  mul11[i].resize(8);
    mul13[i].resize(8); mul14[i].resize(8);
  }
     
  for (int i = 0; i < 16; i++) {          
    for (int j = 0; j < 8; j++) {      
      TFHEpp::SampleExtractIndex<typename privksP::targetP>(mul9_value[i][j], lut_result9[i], j);
      TFHEpp::SampleExtractIndex<typename privksP::targetP>(mul11_value[i][j], lut_result11[i], j);
      TFHEpp::SampleExtractIndex<typename privksP::targetP>(mul13_value[i][j], lut_result13[i], j);
      TFHEpp::SampleExtractIndex<typename privksP::targetP>(mul14_value[i][j], lut_result14[i], j);
    }          
  }
  
  chrono::system_clock::time_point inks_start, inks_end;
  inks_start = chrono::system_clock::now();
  
  for (int i = 0; i < 16; i++) {          
    for (int j = 0; j < 8; j++) {      
      TFHEpp::IdentityKeySwitch<iksP>(mul9[i][j], mul9_value[i][j], ek.getiksk<iksP>());           
      TFHEpp::IdentityKeySwitch<iksP>(mul11[i][j], mul11_value[i][j], ek.getiksk<iksP>());
      TFHEpp::IdentityKeySwitch<iksP>(mul13[i][j], mul13_value[i][j], ek.getiksk<iksP>());
      TFHEpp::IdentityKeySwitch<iksP>(mul14[i][j], mul14_value[i][j], ek.getiksk<iksP>());         
    }          
  }

  inks_end = chrono::system_clock::now();
  double inks_elapsed = chrono::duration_cast<chrono::milliseconds>(inks_end - inks_start).count();
  cout << "Mult Identity keyswitch(16 * 8 times) one round costs: " << inks_elapsed << "ms" << endl;
  iIdks_totaltime += inks_elapsed;

/////////////////////////////// CipheriMixColumns

    std::vector<std::vector<TLWE_0>> tmp;
    tmp.resize(16);
    for (int i = 0; i < 16; i++)
    {
        tmp[i].resize(8);
    }
        XOR_Four(tmp[0], mul14[0], mul11[1], mul13[2], mul9[3]);
        XOR_Four(tmp[1], mul9[0], mul14[1], mul11[2], mul13[3]);        
        XOR_Four(tmp[2], mul13[0], mul9[1], mul14[2], mul11[3]);
        XOR_Four(tmp[3], mul11[0], mul13[1], mul9[2], mul14[3]); 
               
        XOR_Four(tmp[4], mul14[4], mul11[5], mul13[6], mul9[7]);
        XOR_Four(tmp[5], mul9[4], mul14[5], mul11[6], mul13[7]);         
        XOR_Four(tmp[6], mul13[4], mul9[5], mul14[6], mul11[7]);
        XOR_Four(tmp[7], mul11[4], mul13[5], mul9[6], mul14[7]);  
           
        XOR_Four(tmp[8], mul14[8], mul11[9], mul13[10], mul9[11]);
        XOR_Four(tmp[9], mul9[8], mul14[9], mul11[10], mul13[11]);         
        XOR_Four(tmp[10], mul13[8], mul9[9], mul14[10], mul11[11]);
        XOR_Four(tmp[11], mul11[8], mul13[9], mul9[10], mul14[11]); 
                
        XOR_Four(tmp[12], mul14[12], mul11[13], mul13[14], mul9[15]);
        XOR_Four(tmp[13], mul9[12], mul14[13], mul11[14], mul13[15]);         
        XOR_Four(tmp[14], mul13[12], mul9[13], mul14[14], mul11[15]);
        XOR_Four(tmp[15], mul11[12], mul13[13], mul9[14], mul14[15]);   
       //}

	  for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 8; j++)
        {
            TFHEpp::HomCOPY<typename bkP::domainP>(cipher[i][j], tmp[i][j]);
        }
	  }

  }
  cout << "============= test last round ============" << endl;
/////////////////////////////////////There will end 9 rounds////////////////////////////////
  vector<vector<TLWE_0>> B;
    B.resize(16);
    for (int i = 0; i < 16; i++)
    {
      B[i].resize(8);
    }

/////////////////////////////// CipheriMixColumns

       CipheriShiftRows(B, cipher);

  chrono::system_clock::time_point icb_start, icb_end;
  icb_start = chrono::system_clock::now();

  for (int i = 0; i < 16; i++)
  {
    for (int j = 0; j < 8; j++)
    {
      TFHEpp::SM4_CircuitBootstrappingFFT<iksP, bkP, privksP>(bootedTGSW[i][j], B[i][j], ek);
    }
  }
  
  icb_end = chrono::system_clock::now();
  double icb_elapsed = chrono::duration_cast<chrono::milliseconds>(icb_end - icb_start).count();
  cout << " Inverse Circuit bootstrapping(16 * 8 times) one round costs: " << icb_elapsed << "ms" << endl;
  icb_totaltime += icb_elapsed;

  chrono::system_clock::time_point ilut_start, ilut_end;
  ilut_start = chrono::system_clock::now();
  
  for (int i = 0; i < 16; i++)
  {
    MixedPacking(lut_iresult[i], iTable, bootedTGSW[i]);
  }

  ilut_end = chrono::system_clock::now();
  double ilut_elapsed = chrono::duration_cast<chrono::microseconds>(ilut_end - ilut_start).count();
  cout << " iSbox lookup table one round costs: " << ilut_elapsed << "us" << endl;
  ilut_totaltime += ilut_elapsed;

  vector<vector<TLWE_1>> iSbox_value;
  iSbox_value.resize(16);
  for (int i = 0; i < iSbox_value.size(); i++)
  {
    iSbox_value[i].resize(8);
  }
  // SampleExtract level 1
  for (int i = 0; i < 16; i++)
  {
    for (int j = 0; j < 8; j++)
    {
      TFHEpp::SampleExtractIndex<typename privksP::targetP>(iSbox_value[i][j], lut_iresult[i], j);
    }
  }

  chrono::system_clock::time_point iks_start, iks_end;
  iks_start = chrono::system_clock::now();

/////////////////////////////// CipheriSubBytes

  for (int i = 0; i < 16; i++)
  {
    for (int j = 0; j < 8; j++)
    {
    // level 1 -> level 0
    TFHEpp::IdentityKeySwitch<iksP>(B[i][j], iSbox_value[i][j], ek.getiksk<iksP>());
    }
  }

  iks_end = chrono::system_clock::now();
  double iks_elapsed = chrono::duration_cast<chrono::milliseconds>(iks_end - iks_start).count();
  cout << "Inverse Identity keyswitch(16 * 8 times) one round costs: " << iks_elapsed << "ms" << endl;
  iIdks_totaltime += iks_elapsed;

/////////////////////////////// CipherAddRoundKey

      CipherAddRoundKey(B, rka, 0);

  dec_end = chrono::system_clock::now();
  double dec_elapsed = chrono::duration_cast<chrono::milliseconds>(dec_end - dec_start).count();

  {
    ofstream ofs{"../homoData/dec.data", ios::binary};
    cereal::PortableBinaryOutputArchive ar(ofs);
    ar(B);
    cout << "The plaintext  has been serialized." << endl;
  };


  cout << "Inverse Circuitbootstrapping costs: " << icb_totaltime << "ms,  account for " << (icb_totaltime / dec_elapsed) * 100 << "%" << endl;
  cout << "Inverse Lookup table costs: " << ilut_totaltime << "us , account for " << (ilut_totaltime / 1000 / dec_elapsed) * 100 << "%" << endl;
  cout << "Inverse Idks costs: " << iIdks_totaltime << "ms ,  account for " << (iIdks_totaltime / dec_elapsed) * 100 << "%" << endl;
  cout << "Decrypt homo AES using Circuitbootstrapping costs: " << dec_elapsed << "ms" << endl;

//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

  vector<vector<TLWE_0>> rkb;
  {
    ifstream ifs{"../homoData/kb.key", std::ios::binary};
    cereal::PortableBinaryInputArchive ar(ifs);
    ar(rkb);
    cout << "kb a été désérialisé." << endl;
  }  

  vector<TRLWE_1> Table(2);
  {
    ifstream ifs{"../homoData/Sbox.data", ios::binary};
    cereal::PortableBinaryInputArchive ar(ifs);
    ar(Table);
    cout << "Sbox a été désérialisé." << endl;
  }  
  vector<TLWE_0> consByte(8);
  {
    ifstream ifs{"../homoData/consByte.data", ios::binary};
    cereal::PortableBinaryInputArchive ar(ifs);
    ar(consByte);
    cout << "consByte a été désérialisé." << endl;
  }
/////////////////////////////////////

  chrono::system_clock::time_point enc_start, enc_end;
  enc_start = std::chrono::system_clock::now();

    CipherAddRoundKey(B, rkb, 0);


  for (int i = 1; i < 10; i++)
  {
        cout << "================round: " << i << "==================" << endl;
        //  std::cout << ".. circuit bootstrapping...  " << std::endl;
        //======================================================================================
        std::chrono::system_clock::time_point cb_start, cb_end;
        cb_start = std::chrono::system_clock::now();
        for (int i = 0; i < 16; i++)
        {
            for (int j = 0; j < 8; j++)
                TFHEpp::SM4_CircuitBootstrappingFFT<iksP, bkP, privksP>(bootedTGSW[i][j],
                                                                        B[i][j], ek);
        }

        cb_end = std::chrono::system_clock::now();
        double cb_elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(cb_end - cb_start)
                .count();
        std::cout << " Circuit bootstrapping(16 * 8 times) one round costs: " << cb_elapsed << "ms" << std::endl;
        cb_totaltime += cb_elapsed;

        std::vector<TRLWE_1> lut_result(16); //
        std::chrono::system_clock::time_point lut_start, lut_end;
        lut_start = std::chrono::system_clock::now();
        for (int i = 0; i < 16; i++)
        {
            MixedPacking(lut_result[i], Table, bootedTGSW[i]);
        }

        lut_end = std::chrono::system_clock::now();
        double lut_elapsed =
            std::chrono::duration_cast<std::chrono::microseconds>(lut_end - lut_start)
                .count();
        std::cout << " Sbox lookup table one round costs: " << lut_elapsed << "us" << std::endl;
        lut_totaltime += lut_elapsed;

        std::vector<std::vector<TLWE_1>> Sbox_value;
        Sbox_value.resize(16);

        for (int i = 0; i < Sbox_value.size(); i++)
        {
            Sbox_value[i].resize(8);
        }

        // SampleExtract level 1
        for (int i = 0; i < 16; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                TFHEpp::SampleExtractIndex<typename privksP::targetP>(Sbox_value[i][j], lut_result[i], j);
            }
        }

        std::vector<std::vector<TLWE_0>> cipher;
        cipher.resize(16);
        for (int i = 0; i < 16; i++)
        {
            cipher[i].resize(8);
        }

        std::chrono::system_clock::time_point ks_start, ks_end;
        ks_start = std::chrono::system_clock::now();
        for (int i = 0; i < 16; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                // level 1 -> level 0
                TFHEpp::IdentityKeySwitch<iksP>(cipher[i][j], Sbox_value[i][j], ek.getiksk<iksP>());
            }
        }

        ks_end = std::chrono::system_clock::now();
        double ks_elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(ks_end - ks_start)
                .count();
        std::cout << " Identity keyswitch(16 * 8 times) one round costs: " << ks_elapsed << "ms" << std::endl;
        Idks_totaltime += ks_elapsed;


        CipherShiftRows(B, cipher);


        CipherMixColumns(B, consByte);


        CipherAddRoundKey(B, rkb, i);


  }

    cout << "================ round " << 10 << " ==================" << endl;

    // CipherSubBytes();
    std::chrono::system_clock::time_point cb_start, cb_end;
    cb_start = std::chrono::system_clock::now();
    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 8; j++)
            TFHEpp::SM4_CircuitBootstrappingFFT<iksP, bkP, privksP>(bootedTGSW[i][j],
                                                                    B[i][j], ek);
    }

    cb_end = std::chrono::system_clock::now();
    double cb_elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(cb_end - cb_start)
            .count();
    std::cout << " Circuit bootstrapping(16 * 8 times) one round costs: " << cb_elapsed << "ms" << std::endl;
    cb_totaltime += cb_elapsed;

    std::vector<TRLWE_1> lut_result(16); //
    std::chrono::system_clock::time_point lut_start, lut_end;
    lut_start = std::chrono::system_clock::now();
    for (int i = 0; i < 16; i++)
    {
        MixedPacking(lut_result[i], Table, bootedTGSW[i]);
    }

    lut_end = std::chrono::system_clock::now();
    double lut_elapsed =
        std::chrono::duration_cast<std::chrono::microseconds>(lut_end - lut_start)
            .count();
    std::cout << " Sbox lookup table one round costs: " << lut_elapsed << "us" << std::endl;
    lut_totaltime += lut_elapsed;


    std::vector<std::vector<TLWE_1>> Sbox_value;
    Sbox_value.resize(16);

    for (int i = 0; i < Sbox_value.size(); i++)
    {
        Sbox_value[i].resize(8);
    }

    // SampleExtract level 1
    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 8; j++)
        {

            TFHEpp::SampleExtractIndex<typename privksP::targetP>(Sbox_value[i][j], lut_result[i], j);
        }
    }

    // Key Switch to LWE B  on level 0
    std::chrono::system_clock::time_point ks_start, ks_end;

    ks_start = std::chrono::system_clock::now();
    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            // level 1 -> level 0
            TFHEpp::IdentityKeySwitch<iksP>(cipher[i][j], Sbox_value[i][j], ek.getiksk<iksP>());
        }
    }

    ks_end = std::chrono::system_clock::now();
    double ks_elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(ks_end - ks_start)
            .count();
    std::cout << " Identity keyswitch(16 * 8 times) one round costs: " << ks_elapsed << "ms" << std::endl;
    Idks_totaltime += ks_elapsed;


    CipherShiftRows(B, cipher);


    CipherAddRoundKey(B, rkb, 10);

        std::vector<std::vector<TLWE_0>> plain;
        plain.resize(16);
        for (int i = 0; i < 16; i++)
        {
            plain[i].resize(8);
        }
     for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 8; j++)
        {
          plain[i][j] = B[i][j] ;
        }
    }                  

  enc_end = chrono::system_clock::now();
  double enc_elapsed = chrono::duration_cast< chrono::milliseconds>(enc_end - enc_start).count();
  cout << endl;

  {
    ofstream ofs{"../homoData/enc.data", ios::binary};
    cereal::PortableBinaryOutputArchive ar(ofs);
    ar(plain);
    cout << "The enc  has been serialized." << endl;
  };

    cout << "Lookup table SubBytes costs: " << lut_totaltime << "us , account for " << (lut_totaltime / 1000 / enc_elapsed) * 100 << "%" << endl;
    cout << "Circuitbootstrapping costs: " << cb_totaltime << "ms,  account for " << (cb_totaltime / enc_elapsed) * 100 << "%" << endl;
    cout << "Idks costs: " << Idks_totaltime << "ms ,  account for " << (Idks_totaltime / enc_elapsed) * 100 << "%" << endl;
    cout << "Encrypt homo AES using Circuitbootstrapping costs: " << enc_elapsed << "ms" << endl;


    end = chrono::system_clock::now();
    cout << endl;
    double elapsed = chrono::duration_cast<chrono::milliseconds>(end - start).count();
    cout << endl;
    cout << "key switching AES using Circuitbootstrapping costs: " << elapsed << "ms" << std::endl;
    cout << endl;


    // Fermer le fichier
   // ofs.close();
   // return 0;
} 

