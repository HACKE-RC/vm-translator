#include <iostream>
#include "Rex.h"
#include <cstring>

using namespace std;

int main(int argc, const char** argv) {
    ASSEMBLY assembly;
    string outputFileName;

   if (argc > 1){
        if (argc > 3 && strcmp(argv[2],"-o") == 0){
            outputFileName = argv[3];
        }
        else{
            outputFileName = argv[1];
            outputFileName.append(".asm");
        }
    }
   else{
       cout << "Usage: " << argv[0] << " <filename> <optional args>\n";
       cout << "Optional arguments:" << endl;
       cout << "\t-o output.asm" << endl;
       exit(-1);
   }

   Rex translator(argv[1], outputFileName);

   translator.cleanVMCode();
   translator.parseVMCode();
   translator.writeOutput();
   return 0;
}
