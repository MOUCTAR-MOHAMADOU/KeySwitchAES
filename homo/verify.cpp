#include <cassert>
#include <chrono>
#include <iostream>
#include <random>
#include <tfhe++.hpp>

#include <cereal/archives/portable_binary.hpp>
#include <cereal/types/vector.hpp>
#include <fstream>
#include <memory>
#include <vector>
#include "utils.hpp"

using namespace std;

using iksP = TFHEpp::lvl10param;
using bkP = TFHEpp::lvl02param;
using privksP = TFHEpp::lvl21param;

using TLWE_0 = TFHEpp::TLWE<typename bkP::domainP>;
using TLWE_1 = TFHEpp::TLWE<typename privksP::targetP>; // level 1

using TRLWE_1 = TFHEpp::TRLWE<typename privksP::targetP>; // level 1




void verify() {
  /*  //-------------------------------------------------------
      // Ouvrir un fichier pour écrire
    ofstream ofs("verify.txt");
    if (!ofs) {
        std::cerr << "Erreur lors de l'ouverture du fichier." << std::endl;
        return 1;
    }
    // Sauvegarder le buffer original de std::cout
    streambuf* originalCoutBuffer = std::cout.rdbuf();
    // Rediriger std::cout vers le fichier
    cout.rdbuf(ofs.rdbuf());
    // Rétablir la sortie standard vers le terminal
    cout.rdbuf(originalCoutBuffer);
  //-------------------------------------------------------
  */
  unique_ptr<TFHEpp::SecretKey> sk1 = make_unique<TFHEpp::SecretKey>();
  unique_ptr<TFHEpp::SecretKey> sk2 = make_unique<TFHEpp::SecretKey>();
  {
    ifstream ifs("../AliceData/sk1.key", ios::binary);
    cereal::PortableBinaryInputArchive ar(ifs);
    sk1->serialize(ar); // Utilisez sk-> ici
    cout << "The Alice SecretKey sk1 a été désérialisé." << endl;
  }  
  {
    ifstream ifs("../BobData/sk2.key", ios::binary);
    cereal::PortableBinaryInputArchive ar(ifs);
    sk2->serialize(ar); // Utilisez sk-> ici
    cout << "The Bob SecretKey sk2 a été désérialisé." << endl;
  }  
  vector<vector<TLWE_0>> B;
  {
    ifstream ifs{"../homoData/dec.data", ios::binary};
    cereal::PortableBinaryInputArchive ar(ifs);
    ar(B);
    cout << "The dec has been serialized." << endl;
  } 
  // import input
    vector<vector<TLWE_0>> plain;
  {
    ifstream ifs{"../homoData/enc.data", ios::binary};
    cereal::PortableBinaryInputArchive ar(ifs);
    ar(plain);
    cout << "The enc key has been serialized." << endl;
  }  
        cout << endl;
  cout << "============= verification ============" << endl;
          cout << endl;
    cout <<"After ka Decrypt ciphertext : " << endl;
        for (int i = 0; i < 16; i++)
        {
            int dec_hex = 0;
            int dec_bin[8];
            for (int j = 0; j < 8; j++)
            {
                // typename P::T a = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>();
                dec_bin[j] = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>(B[i][j], sk1->key.get<typename bkP::domainP>());
                // bootsSymDecrypt(&rk[0][i][j], key);
            }
            BinStrToHex(dec_hex, dec_bin);
            cout << hex << dec_hex << " ";
        }
        cout << endl;  
   cout <<"After kb Encrypt plaintext : " << endl;
        for (int i = 0; i < 16; i++)
        {
            int dec_hex = 0;
            int dec_bin[8];
            for (int j = 0; j < 8; j++)
            {
                // typename P::T a = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>();
                dec_bin[j] = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>(plain[i][j], sk2->key.get<typename bkP::domainP>());
                // bootsSymDecrypt(&rk[0][i][j], key);
            }
            BinStrToHex(dec_hex, dec_bin);
            cout << hex << dec_hex << " ";
        }
   cout << endl;
 
  
  // Fermer le fichier
  ////ofs.close();  
}
//int main()
//{
//  verify();
//  return 0;
//}