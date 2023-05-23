#ifndef VM_TRANSLATOR_REX_H
#define VM_TRANSLATOR_REX_H

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <map>
#include <algorithm>
#include <cctype>
#include <filesystem>

typedef std::vector<std::string> VMCODE;
typedef std::vector<std::string> ASSEMBLY;

class Rex {
private:
   std::string m_fData;
   VMCODE m_vmcode;
   std::string m_outfName;
   ASSEMBLY m_assembly;
   std::string m_returnLabel;

   enum insType {
       MONOINS = 1,
       DUOINS,
       CONDITIONAL_BRANCH,
       UNCONDITIONAL_BRANCH,
       CALL,
       LABEL,
       ERROR_INVALID_INSTRUCTION = -7,
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
       MNEMONIC_EQ,
       MNEMONIC_CALL,
       MNEMONIC_IF_GO_TO,
       MNEMONIC_GO_TO,
       MNEMONIC_RETURN,
       MNEMONIC_LABEL,
       MNEMONIC_FUNCTION
   };

    std::map<std::string, mnemonicType> m_strMnemonicType = {{"push", MNEMONIC_PUSH}, {"pop", MNEMONIC_POP}, {"add", MNEMONIC_ADD},
                                                             {"sub", MNEMONIC_SUB}, {"and", MNEMONIC_AND},{"or", MNEMONIC_OR},
                                                             {"not", MNEMONIC_NOT}, {"lt", MNEMONIC_LT}, {"gt", MNEMONIC_GT},
                                                             {"neg", MNEMONIC_NEG}, {"eq", MNEMONIC_EQ}, {"if-goto", MNEMONIC_IF_GO_TO},
                                                             {"goto", MNEMONIC_GO_TO}, {"return", MNEMONIC_RETURN}, {"call", MNEMONIC_CALL},
                                                             {"label", MNEMONIC_LABEL}, {"function", MNEMONIC_FUNCTION}};

public:
   struct instructionInfo{
            insType instructionType;
            std::string functionName;
            std::string nArgs;

            std::string mnemonic;
            std::string segment;
            std::string parameter;
            mnemonicType mnemonictype;
    };

private:
    int m_routine = 1;
    std::map<std::string, std::string> m_constAddr = {{"local", "1"}, {"argument", "2"},
                                                      {"this",  "3"}, {"that", "4"},
                                                      {"temp",  "5"}, {"pointer", "3"},
                                                      {"SP", "0"}};

    static void printInsInfo(instructionInfo& insInf);

public:
    enum statusCode {
        ERROR_FILE_NOT_FOUND = -1,
    };

    VMCODE validMonoIns = {"add", "sub", "eq", "lt", "gt", "not", "or", "and", "neg", "return"};
    VMCODE validDuoIns = {"push", "pop", "label", "if-goto", "goto", "call", "function"};
    VMCODE validSegments = {"constant", "local", "argument", "this", "that", "temp", "pointer"};


public:
        explicit Rex(std::string fName, std::string outfName);
        void cleanVMCode();
        ASSEMBLY parseVMCode();
        void printVMCode();
        void writeOutput();

private:
    instructionInfo getVMInsInfo(std::string& code, ASSEMBLY& assembly);
    static bool isValid(VMCODE const& vec, std::string& str);
    static bool isNumber(std::string& str);
    mnemonicType identifyInstruction(std::string& str);
    static void to_lower(std::string& str);


private:
    void translatePush(instructionInfo insInfo, ASSEMBLY& assembly);
    void translatePop(instructionInfo insInfo, ASSEMBLY& assembly);
    void translateArithmetic(instructionInfo insInfo, ASSEMBLY& assembly);
    void translateEquals(instructionInfo insInfo, ASSEMBLY& assembly);
    void translateComparison(instructionInfo insInfo, ASSEMBLY& assembly);
    void translateBinaryOp(instructionInfo insInfo, ASSEMBLY& assembly);
    void translateBinaryOp2(instructionInfo insInfo, ASSEMBLY& assembly);
    void translateCall(instructionInfo insInfo, ASSEMBLY& assembly);
    void translateLabel(instructionInfo insInfo, ASSEMBLY& assembly);
    void translateGoTo(instructionInfo insInfo, ASSEMBLY& assembly);
    void translateReturn(instructionInfo insInfo, ASSEMBLY& assembly);
    void translateFunction(instructionInfo insInfo, ASSEMBLY& assembly);

};
#endif //VM_TRANSLATOR_REX_H
