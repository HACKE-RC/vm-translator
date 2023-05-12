#ifndef VM_TRANSLATOR_REX_H
#define VM_TRANSLATOR_REX_H

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <map>


typedef std::vector<std::string> VMCODE;
typedef std::vector<std::string> ASSEMBLY;

class Rex {
private:
   std::string m_fData;
   VMCODE m_vmcode;
   std::string m_outfName;
   ASSEMBLY m_assembly;

   enum insType {
       MONOINS = 1,
       DUOINS
   };

   enum mnemonicType{
       MNEMONIC_PUSH,
       MNEMONIC_POP,
       MNEMONIC_ADD,
       MNEMONIC_SUB,
       MNEMONIC_AND,
       MNEMONIC_OR,
       MNEMONIC_NOT,
       MNEMONIC_LT,
       MNEMONIC_GT,
       MNEMONIC_NEG,
       MNEMONIC_EQ
   };

    std::map<std::string, mnemonicType> m_strMnemonicType = {{"push", MNEMONIC_PUSH}, {"pop", MNEMONIC_POP}, {"add", MNEMONIC_ADD}, {"sub", MNEMONIC_SUB}, {"and", MNEMONIC_AND}, {"or", MNEMONIC_OR}, {"not", MNEMONIC_NOT}, {"lt", MNEMONIC_LT}, {"gt", MNEMONIC_GT}, {"neg", MNEMONIC_NEG}, {"eq", MNEMONIC_EQ}};

public:
   struct instructionInfo{
            int insType;

            std::string mnemonic;
            std::string segment;
            std::string parameter;
            mnemonicType mnemonictype;
    };

private:
    std::map<std::string, std::string> m_segAddr = {{"local", "1"}, {"argument", "2"},
                                                    {"this", "3"}, {"that", "4"},
                                                    {"temp", "5"}, {"pointer", "3"}};

    static void printInsInfo(instructionInfo& insInf);

public:
    enum statusCode {
        ERROR_FILE_NOT_FOUND = -1,
        ERROR_INVALID_VMCODE = -7,
    };

    VMCODE validMonoIns = {"add", "sub", "eq", "lt", "gt", "not", "or", "and", "neg"};
    VMCODE validDuoIns = {"push", "pop"};
    VMCODE validSegments = {"constant", "local", "argument", "this", "that", "temp", "pointer"};


public:
        explicit Rex(std::string fName, std::string outfName);
        void cleanVMCode();
        ASSEMBLY parseVMCode();
        void printVMCode();
        statusCode writeOutput();

private:
    instructionInfo getVMInsInfo(std::string& code);
    static bool isValid(VMCODE const& vec, std::string& str);
    static bool isNumber(std::string& str);
    mnemonicType identifyInstruction(std::string& str);
};

#endif //VM_TRANSLATOR_REX_H
