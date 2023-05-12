#include "Rex.h"

Rex::Rex(std::string fName, std::string outfName){
    std::ifstream fStream(fName);

    if (!fStream.good()){
        std::cerr << "ERR: " << "File not found!" << std::endl;
        std::exit(ERROR_FILE_NOT_FOUND);
    }

   while (getline(fStream, m_fData)) {
       m_vmcode.push_back(m_fData);
   }

   m_outfName = outfName;
}

void Rex::cleanVMCode() {
    VMCODE tokens;
    std::string tok;

    for (auto token: this->m_vmcode){
        if (token.starts_with("/") || token.empty()) {continue;}

        auto slash_idx = token.find("/");

        if (slash_idx != std::string::npos){
            tok = token.substr(0, slash_idx);
        }
        else{
            tok = token;
        }

        tokens.push_back(tok);
    }
    this->m_vmcode = tokens;
}

void Rex::printVMCode() {
    for (auto token: this->m_vmcode){
        std::cout << token << std::endl;
    }
}

bool Rex::isValid(VMCODE const& vec, std::string& str){
    if (std::count(vec.begin(), vec.end(), str)){
        return true;
    }
    return false;
}

Rex::instructionInfo Rex::getVMInsInfo(std::string &code){
    std::string duoIns;
    std::string duoSeg;
    std::string duoParam;
    instructionInfo insInfo;

    auto space_idx = code.find(' ');
    auto space_idx2 = code.find(' ', space_idx + 1);
    auto space_idx_last = code.find_last_of(' ');
    if (space_idx == std::string::npos){
        //  Mono mnemonicType.
        if (isValid(validMonoIns, code)){
            insInfo.mnemonic = code;
            insInfo.mnemonictype = identifyInstruction(insInfo.mnemonic);
            insInfo.insType = MONOINS;
            return insInfo;
        }
        else{
            insInfo.insType = ERROR_INVALID_VMCODE;
            return insInfo;
        }
    }
    else
    {
        // Duo mnemonicType
        duoIns = code.substr(0, space_idx);
        duoSeg = code.substr(space_idx+1);
        space_idx2 = duoSeg.find(' ');
        duoSeg = duoSeg.substr(0, space_idx2);
        duoParam = code.substr(space_idx_last + 1);
        if (isValid(validDuoIns, duoIns) && isValid(validSegments, duoSeg) && isNumber(duoParam)){
            insInfo.insType = DUOINS;
            insInfo.mnemonic = duoIns;
            insInfo.segment = duoSeg;
            insInfo.parameter = duoParam;
            insInfo.mnemonictype = identifyInstruction(insInfo.mnemonic);
            return insInfo;
        }
        else
        {
            insInfo.insType = ERROR_INVALID_VMCODE;
            return insInfo;
        }
    }
}

ASSEMBLY Rex::parseVMCode() {
    instructionInfo insInfo;
    ASSEMBLY assembly;
    int routine = 0;

    for (auto token: this->m_vmcode) {
        insInfo = getVMInsInfo(token);

        if (insInfo.insType == ERROR_INVALID_VMCODE) {
            std::cerr << "ERROR: INVALID VM INSTRUCTION -> " << token << std::endl;
            std::exit(ERROR_INVALID_VMCODE);
        }

        assembly.push_back("// " + token);

        switch (insInfo.mnemonictype){
            case MNEMONIC_PUSH:
                if (insInfo.segment == "constant"){
                    assembly.push_back("@" + insInfo.parameter);
                    assembly.push_back("D=A");
                    assembly.push_back("@SP");
                    assembly.push_back("A=M");
                    assembly.push_back("M=D");
                    assembly.push_back("@SP");
                    assembly.push_back("M=M+1");
                    continue;
                }
                else if (insInfo.segment == "static"){
                    assembly.push_back("@static." + insInfo.parameter);
                    assembly.push_back("D=M");
                }
                else if (insInfo.segment == "pointer"){
                    if (insInfo.parameter == "0"){
                        // this
                        insInfo.segment = "this";
                    }
                    else{
                        // that
                        insInfo.segment = "that";
                    }
                    assembly.push_back("@" + m_segAddr[insInfo.segment]);
                    assembly.push_back("D=M");
                }
                else {
                    assembly.push_back("// D = *(" + insInfo.segment + " + " + insInfo.parameter + ")");
                    assembly.push_back("@" + insInfo.parameter);
                    assembly.push_back("D=A");
                    assembly.push_back("@" + m_segAddr[insInfo.segment]);
                    assembly.push_back("A=M");
                    assembly.push_back("A=D+A");
                    assembly.push_back("D=M");
                }

                assembly.push_back("// *SP = D");
                assembly.push_back("@SP");
                assembly.push_back("A=M");
                assembly.push_back("M=D");

                assembly.push_back("// SP++");
                assembly.push_back("@SP");
                assembly.push_back("M=M+1");
                continue;
            case MNEMONIC_POP:
                if (insInfo.segment == "static"){
                    assembly.push_back("@static." + insInfo.parameter);
                    assembly.push_back("D=A");
                }
                else if (insInfo.segment == "pointer"){
                    if (insInfo.parameter == "0"){
                        // this
                        insInfo.segment = "this";
                    }
                    else{
                        // that
                        insInfo.segment = "that";
                    }
                    assembly.push_back("@" + m_segAddr[insInfo.segment]);
                    assembly.push_back("D=A");
                    assembly.push_back("@temp");
                    assembly.push_back("M=D");
                    assembly.push_back("// D = *(SP - 1)");
                    assembly.push_back("@SP");
                    assembly.push_back("A=M-1");
                    assembly.push_back("D=M");
                    assembly.push_back("@temp");
                    assembly.push_back("A=M");
                    assembly.push_back("M=D");
                    assembly.push_back("// SP--");
                    assembly.push_back("@SP");
                    assembly.push_back("M=M-1");
                    continue;
                }
                else {
                    assembly.push_back("// D = *(" + insInfo.segment + " + " + insInfo.parameter + ")");
                    assembly.push_back("@" + insInfo.parameter);
                    assembly.push_back("D=A");
                    assembly.push_back("@" + m_segAddr[insInfo.segment]);
                    assembly.push_back("A=M");
                    assembly.push_back("A=D+A");
                    assembly.push_back("D=A");
                }

                assembly.push_back("// temp = D");
                assembly.push_back("@temp");
                assembly.push_back("M=D");

                assembly.push_back("// D = *(SP - 1)");
                assembly.push_back("@SP");
                assembly.push_back("A=M-1");
                assembly.push_back("D=M");

                assembly.push_back("// temp = D");
                assembly.push_back("@temp");
                assembly.push_back("A=M");
                assembly.push_back("M=D");

                assembly.push_back("// SP--");
                assembly.push_back("@SP");
                assembly.push_back("M=M-1");
                continue;
            case MNEMONIC_ADD:
                assembly.push_back("// D = *(SP-1); A = (*SP-2); D = D + A;");
                assembly.push_back("@SP");
                assembly.push_back("A=M-1");
                assembly.push_back("D=M");
                assembly.push_back("A=A-1");
                assembly.push_back("AD=D+M");

                assembly.push_back("// SP = SP - 2; *SP = D");
                assembly.push_back("@SP");
                assembly.push_back("M=M-1");
                assembly.push_back("M=M-1");
                assembly.push_back("A=M");
                assembly.push_back("M=D");

                // because SP needs to be incremented everytime a value is put in the stack.
                assembly.push_back("// SP++");
                assembly.push_back("@SP");
                assembly.push_back("M=M+1");
                continue;
            case MNEMONIC_SUB:
                assembly.push_back("// D = *(SP-1); M = *(SP-2); D = M - D;");
                assembly.push_back("@SP");
                assembly.push_back("A=M-1");
                assembly.push_back("D=M");
                assembly.push_back("A=A-1");
                assembly.push_back("AD=M-D");

                assembly.push_back("// SP = SP - 2; *SP = D");
                assembly.push_back("@SP");
                assembly.push_back("M=M-1");
                assembly.push_back("M=M-1");
                assembly.push_back("A=M");
                assembly.push_back("M=D");

                // because SP needs to be incremented everytime a value is put in the stack.
                assembly.push_back("// SP++");
                assembly.push_back("@SP");
                assembly.push_back("M=M+1");
                continue;
            case MNEMONIC_EQ:
                assembly.push_back("// D = *(SP-1); M = *(SP-2); D = M - D;");
                assembly.push_back("@SP");
                assembly.push_back("A=M-1");
                assembly.push_back("D=M");
                assembly.push_back("A=A-1");
                assembly.push_back("AD=M-D");
                assembly.push_back("@branch_false_" + std::to_string(routine));
                assembly.push_back("D;JNE");
                assembly.push_back("D=-1");
                assembly.push_back("@continue_" + std::to_string(routine));
                assembly.push_back("0;JMP");
                assembly.push_back("(branch_false_" + std::to_string(routine) + ")");
                assembly.push_back("@0");
                assembly.push_back("D=A");
                assembly.push_back("(continue_" + std::to_string(routine) + ")");
                assembly.push_back("@SP");
                assembly.push_back("A=M-1");
                assembly.push_back("A=A-1");
                assembly.push_back("M=D");
                assembly.push_back("@SP");
                assembly.push_back("M=M-1");
                routine++;
                continue;
            case MNEMONIC_LT:
            case MNEMONIC_GT:
                assembly.push_back("// D = *(SP-1); M = *(SP-2); D = M - D;");
                assembly.push_back("@SP");
                assembly.push_back("A=M-1");
                assembly.push_back("D=M");
                assembly.push_back("A=A-1");
                assembly.push_back("AD=M-D");
                assembly.push_back("@branch_false_" + std::to_string(routine));
                if (insInfo.mnemonictype == MNEMONIC_GT){
                    assembly.push_back("D;JLE");
                }
                else{
                    assembly.push_back("D;JGE");
                }
                assembly.push_back("D=-1");
                assembly.push_back("@continue_" + std::to_string(routine));
                assembly.push_back("0;JMP");
                assembly.push_back("(branch_false_" + std::to_string(routine) + ")");
                assembly.push_back("@0");
                assembly.push_back("D=A");
                assembly.push_back("(continue_" + std::to_string(routine) + ")");
                assembly.push_back("@SP");
                assembly.push_back("A=M-1");
                assembly.push_back("A=A-1");
                assembly.push_back("M=D");
                assembly.push_back("@SP");
                assembly.push_back("M=M-1");
                routine++;
                continue;
            case MNEMONIC_NEG:
            case MNEMONIC_NOT:
                assembly.push_back("@SP");
                assembly.push_back("A=M-1");
                assembly.push_back("D=!M");
                if (insInfo.mnemonictype == MNEMONIC_NEG){
                    assembly.push_back("D=D+1");
                }
                assembly.push_back("M=D");
                continue;
            case MNEMONIC_AND:
            case MNEMONIC_OR:
                assembly.push_back("@SP");
                assembly.push_back("A=M-1");
                assembly.push_back("D=M");
                assembly.push_back("A=A-1");
                if (insInfo.mnemonictype == MNEMONIC_OR){
                    assembly.push_back("M=D|M");
                }
                else{
                    assembly.push_back("M=D&M");
                }
                assembly.push_back("@SP");
                assembly.push_back("M=M-1");
                continue;
            default:
                continue;
        }
    }

    this->m_assembly = assembly;
    return assembly;
}


bool Rex::isNumber(std::string& str) {
     return !str.empty() && str.find_first_not_of("0123456789") == std::string::npos;
}

Rex::mnemonicType Rex::identifyInstruction(std::string& str) {
    return m_strMnemonicType[str];
}

void Rex::printInsInfo(Rex::instructionInfo &insInf) {
    std::cout << "--- mnemonicType ---" << std::endl;
    std::cout << "Type: " << insInf.insType << std::endl;
    std::cout << "Ins: " << insInf.mnemonic << std::endl;

    if (insInf.insType == DUOINS)
    {
    std::cout << "Seg: " << insInf.segment << std::endl;
    std::cout << "Param: " << insInf.parameter << std::endl;
    }
}

Rex::statusCode Rex::writeOutput() {
    std::ofstream output(this->m_outfName);
    for (auto line: this->m_assembly){
        line = line.append("\n");
        output.write(line.c_str(), line.length());
    }
}
