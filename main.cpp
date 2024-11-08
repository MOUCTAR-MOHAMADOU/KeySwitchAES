#include <fstream> 
#include <iostream>
#include <cstdlib>

using namespace std;

// Déclaration des fonctions externes
extern void file_gen();  // Fonction à définir dans file_gen.cpp
extern void k_switch();   // Fonction à définir dans k_switch.cpp
extern void verify();     // Fonction à définir dans verify.cpp

int main() {
      //-------------------------------------------------------
      // Ouvrir un fichier pour écrire
    /*ofstream ofs{"../homoData/sortie.txt", ios::binary};  
    // Sauvegarder le buffer original de std::cout
    streambuf* originalCoutBuffer = cout.rdbuf(ofs.rdbuf());

    // Rediriger std::cout vers le fichier
    cout.rdbuf(ofs.rdbuf());
    // Rétablir la sortie standard vers le terminal
    cout.rdbuf(originalCoutBuffer);
  //-------------------------------------------------------
*/
    // Appeler la fonction de génération de fichiers
    cout << "Exécution de file_gen..." << endl;
    file_gen();

    // Appeler la fonction de commutation de clés
    cout << "Exécution de k_switch..." << endl;
    k_switch();

    // Appeler la fonction de vérification
    cout << "Exécution de verify..." << endl;
    verify();

    // Fermer le fichier
    //ofs.close();

    return 0;
}
