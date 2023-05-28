#include "Rex.h"

Rex::Rex(std::string fName, std::string outfName){
    std::vector<std::string> fNames = {};

    if (std::filesystem::is_directory(fName.c_str())){

        for (auto entry: std::filesystem::directory_iterator(fName.c_str())){
            if (std::filesystem::is_regular_file(entry)){
                auto filename = entry.path().filename().string();
                auto full_filename = fName + "\\" + filename;
                if (filename.ends_with(".vm") && std::find(fNames.begin(), fNames.end(), full_filename) == fNames.end()){
                    fNames.push_back(full_filename);
                }
            }
        }
       if (std::filesystem::is_directory(outfName.substr(0, outfName.find_last_of("\\")))){
           this->m_outfName = outfName;
       }
       else{
           this->m_outfName = fName + "\\" +  outfName;
       }
    }
    else{
        fNames.push_back(fName);
        this->m_outfName = outfName.append(".asm");
    }
    for (auto file: fNames){
        std::cout << file << std::endl;
        std::ifstream fStream(file);

        if (!fStream.good()){
            std::cerr << "ERR: " << "File not found!" << std::endl;
            std::exit(ERROR_FILE_NOT_FOUND);
        }

       while (getline(fStream, m_fData)) {
           m_vmcode.push_back(m_fData);
       }
    }

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

Rex::instructionInfo Rex::getVMInsInfo(std::string &code, ASSEMBLY& assembly){
    std::string duoIns;
    std::string duoSeg;
    std::string duoParam;
    instructionInfo insInfo;
    if (!(code.starts_with("goto"))){
        assembly.push_back("// " + code);
    }
    auto codeNoSpace = std::find_if_not(code.rbegin(), code.rend(), ::isspace).base();
    std::string code_cleaned(code.begin(), codeNoSpace);
    auto space_idx = code_cleaned.find(' ');
    auto space_idx2 = code_cleaned.find(' ', space_idx + 1);
    auto space_idx_last = code_cleaned.find_last_of(' ');
    if (space_idx == std::string::npos){
        //  Mono mnemonicType.
        if (isValid(validMonoIns, code_cleaned)){
            insInfo.mnemonic = code_cleaned;
            insInfo.mnemonictype = identifyInstruction(insInfo.mnemonic);
            insInfo.instructionType = MONOINS;
            return insInfo;
        }
        else{
            insInfo.instructionType = ERROR_INVALID_INSTRUCTION;
            return insInfo;
        }
    }
    else
    {
        // Duo mnemonicType
        duoIns = code_cleaned.substr(0, space_idx);
        to_lower(duoIns);
        code_cleaned = code_cleaned.substr(space_idx+1);
        space_idx = code_cleaned.find(" ");
        duoSeg = code_cleaned.substr(0, space_idx);

        code_cleaned = code_cleaned.substr(space_idx+1);
        duoParam = code_cleaned;
        duoParam.erase(remove(duoParam.begin(), duoParam.end(), ' '), duoParam.end());
        if (isValid(validDuoIns, duoIns) ){
            if (duoIns == "call" || duoIns == "goto" || duoIns == "if-goto" || duoIns == "label" || duoIns == "function"){
                if (duoIns == "call" || duoIns == "label" || duoIns == "function"){
                 // function is also a type of label;
                    insInfo.instructionType = duoIns == "call" ? CALL : LABEL;
                    insInfo.nArgs = duoParam;
                }
                else{
                    insInfo.instructionType = duoIns == "goto" ? UNCONDITIONAL_BRANCH : CONDITIONAL_BRANCH;
                }
                insInfo.mnemonic = duoIns;
                insInfo.functionName = duoSeg;
                insInfo.mnemonictype = identifyInstruction(insInfo.mnemonic);
                return insInfo;
            }
            else if (!(isNumber(duoParam)) && !(isValid(validSegments, duoSeg)) && !(duoSeg.starts_with("@")) && !(duoSeg == "SP")){
                insInfo.instructionType = ERROR_INVALID_INSTRUCTION;
                return insInfo;
            }

            insInfo.instructionType = DUOINS;
            insInfo.mnemonic = duoIns;
            insInfo.segment = duoSeg;
            insInfo.parameter = duoParam;
            insInfo.mnemonictype = identifyInstruction(insInfo.mnemonic);
            return insInfo;
        }
        else
        {
            insInfo.instructionType = ERROR_INVALID_INSTRUCTION;
            return insInfo;
        }
    }
}

ASSEMBLY Rex::parseVMCode() {
    instructionInfo insInfo;
    ASSEMBLY assembly;

    assembly.push_back("// Initialise stack pointer to 256");
    assembly.push_back("@256");
    assembly.push_back("D=A");
    assembly.push_back("@SP");
    assembly.push_back("M=D");

    std::string instruction = "call Sys.init 0";
    instructionInfo temp_Info = getVMInsInfo(instruction, assembly);
    translateCall(temp_Info, assembly);

    for (auto token: this->m_vmcode) {
        insInfo = getVMInsInfo(token, assembly);

        if (insInfo.instructionType == ERROR_INVALID_INSTRUCTION) {
            std::cerr << "ERROR: INVALID VM INSTRUCTION -> " << token << std::endl;
            std::exit(ERROR_INVALID_INSTRUCTION);
        }


        switch (insInfo.mnemonictype){
            case MNEMONIC_PUSH:
                translatePush(insInfo, assembly);
                continue;
            case MNEMONIC_POP:
                translatePop(insInfo, assembly);
                continue;
            case MNEMONIC_ADD:
            case MNEMONIC_SUB:
                translateArithmetic(insInfo, assembly);
                continue;
            case MNEMONIC_EQ:
                translateEquals(insInfo, assembly);
                continue;
            case MNEMONIC_LT:
            case MNEMONIC_GT:
                translateComparison(insInfo, assembly);
                continue;
            case MNEMONIC_NEG:
            case MNEMONIC_NOT:
                translateBinaryOp(insInfo, assembly);
                continue;
            case MNEMONIC_AND:
            case MNEMONIC_OR:
                translateBinaryOp2(insInfo, assembly);
                continue;
            case MNEMONIC_IF_GO_TO:
            case MNEMONIC_GO_TO:
                translateGoTo(insInfo, assembly);
                continue;
            case MNEMONIC_LABEL:
                translateLabel(insInfo, assembly);
                continue;
            case MNEMONIC_FUNCTION:
                translateFunction(insInfo, assembly);
                continue;
            case MNEMONIC_RETURN:
                translateReturn(insInfo, assembly);
                continue;
            case MNEMONIC_CALL:
                translateCall(insInfo, assembly);
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
    std::cout << "Type: " << insInf.instructionType << std::endl;
    std::cout << "Ins: " << insInf.mnemonic << std::endl;

    if (insInf.instructionType == DUOINS)
    {
    std::cout << "Seg: " << insInf.segment << std::endl;
    std::cout << "Param: " << insInf.parameter << std::endl;
    }
}

void Rex::writeOutput() {
    std::ofstream output(this->m_outfName);
    for (auto line: this->m_assembly){
        line = line.append("\n");
        output.write(line.c_str(), line.length());
    }
}

void Rex::translatePush(Rex::instructionInfo insInfo, ASSEMBLY& assembly) {
    if (insInfo.segment == "SP"){
        assembly.push_back("@SP");
        assembly.push_back("D=M");
    }
    else if (insInfo.segment.starts_with("@")){
        assembly.push_back("@" + insInfo.segment.substr(1));
        assembly.push_back("D=A");
    }
    else if (insInfo.parameter == insInfo.segment){
        assembly.push_back("@" + m_constAddr[insInfo.segment]);
        assembly.push_back("D=M");
    }
    else if (insInfo.segment == "constant"){
        assembly.push_back("@" + insInfo.parameter);
        assembly.push_back("D=A");
        assembly.push_back("@SP");
        assembly.push_back("A=M");
        assembly.push_back("M=D");
        assembly.push_back("@SP");
        assembly.push_back("M=M+1");
        return;
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
        assembly.push_back("@" + m_constAddr[insInfo.segment]);
        assembly.push_back("D=M");
    }

    else {
        assembly.push_back("// D = *(" + insInfo.segment + " + " + insInfo.parameter + ")");
        assembly.push_back("@" + insInfo.parameter);
        assembly.push_back("D=A");
        assembly.push_back("@" + m_constAddr[insInfo.segment]);
        assembly.push_back("A=D+M");
        assembly.push_back("D=M");
    }

    assembly.push_back("// *SP = D");
    assembly.push_back("@SP");
    assembly.push_back("A=M");
    assembly.push_back("M=D");

    assembly.push_back("// SP++");
    assembly.push_back("@SP");
    assembly.push_back("M=M+1");
}

void Rex::translatePop(Rex::instructionInfo insInfo, ASSEMBLY &assembly) {
    if (insInfo.parameter == insInfo.segment){
        assembly.push_back("@" + m_constAddr[insInfo.segment]);
        assembly.push_back("D=A");
    }
    else if (insInfo.segment == "static"){
        assembly.push_back("@static." + insInfo.parameter);
        assembly.push_back("D=A");
    }
    else if (insInfo.segment == "pointer"){
        if (insInfo.parameter == "0"){
            insInfo.segment = "this";
        }
        else{
            // that
            insInfo.segment = "that";
        }
        assembly.push_back("@" + m_constAddr[insInfo.segment]);
        assembly.push_back("D=A");
        assembly.push_back("@" + m_constAddr["temp"]);
        assembly.push_back("M=D");
        assembly.push_back("// D = *(SP - 1)");
        assembly.push_back("@SP");
        assembly.push_back("A=M-1");
        assembly.push_back("D=M");
        assembly.push_back("@" + m_constAddr["temp"]);
        assembly.push_back("A=M");
        assembly.push_back("M=D");
        assembly.push_back("// SP--");
        assembly.push_back("@SP");
        assembly.push_back("M=M-1");
        return;
    }
    else {
        assembly.push_back("// D = *(" + insInfo.segment + " + " + insInfo.parameter + ")");
        assembly.push_back("@" + insInfo.parameter);
        assembly.push_back("D=A");
        assembly.push_back("@" + m_constAddr[insInfo.segment]);
        if (insInfo.segment == "temp"){
            assembly.push_back("D=D+A");
        }
        else{
            assembly.push_back("D=D+M");
        }
//        assembly.push_back("D=A");
    }

        assembly.push_back("// temp_var = D");
        assembly.push_back("@temp_var");
        assembly.push_back("M=D");

        assembly.push_back("// D = *(SP - 1)");
        assembly.push_back("@SP");
        assembly.push_back("A=M-1");
        assembly.push_back("D=M");

        assembly.push_back("// temp_var = D");
        assembly.push_back("@temp_var");
        assembly.push_back("A=M");
        assembly.push_back("M=D");

        assembly.push_back("// SP--");
        assembly.push_back("@SP");
        assembly.push_back("M=M-1");
}

void Rex::translateArithmetic(Rex::instructionInfo insInfo, ASSEMBLY &assembly) {
    assembly.push_back("// D = *(SP-1); M = *(SP-2); D = M - D;");
    assembly.push_back("@SP");
    assembly.push_back("A=M-1");
    assembly.push_back("D=M");
    assembly.push_back("A=A-1");
    if (insInfo.mnemonictype == MNEMONIC_ADD){
        assembly.push_back("AD=D+M");
    }
    else{
        assembly.push_back("AD=M-D");
    }

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
}

void Rex::translateEquals(Rex::instructionInfo insInfo, ASSEMBLY &assembly) {
    assembly.push_back("// D = *(SP-1); M = *(SP-2); D = M - D;");
    assembly.push_back("@SP");
    assembly.push_back("A=M-1");
    assembly.push_back("D=M");
    assembly.push_back("A=A-1");
    assembly.push_back("AD=M-D");
    assembly.push_back("@branch_false_" + std::to_string(m_routine));
    assembly.push_back("D;JNE");
    assembly.push_back("D=-1");
    assembly.push_back("@continue_" + std::to_string(m_routine));
    assembly.push_back("0;JMP");
    assembly.push_back("(branch_false_" + std::to_string(m_routine) + ")");
    assembly.push_back("@0");
    assembly.push_back("D=A");
    assembly.push_back("(continue_" + std::to_string(m_routine) + ")");
    assembly.push_back("@SP");
    assembly.push_back("A=M-1");
    assembly.push_back("A=A-1");
    assembly.push_back("M=D");
    assembly.push_back("@SP");
    assembly.push_back("M=M-1");
    m_routine++;
}

void Rex::translateComparison(Rex::instructionInfo insInfo, ASSEMBLY &assembly) {
    assembly.push_back("// D = *(SP-1); M = *(SP-2); D = M - D;");
    assembly.push_back("@SP");
    assembly.push_back("A=M-1");
    assembly.push_back("D=M");
    assembly.push_back("A=A-1");
    assembly.push_back("AD=M-D");
    assembly.push_back("@branch_false_" + std::to_string(m_routine));
    if (insInfo.mnemonictype == MNEMONIC_GT){
        assembly.push_back("D;JLE");
    }
    else{
        assembly.push_back("D;JGE");
    }
    assembly.push_back("D=-1");
    assembly.push_back("@continue_" + std::to_string(m_routine));
    assembly.push_back("0;JMP");
    assembly.push_back("(branch_false_" + std::to_string(m_routine) + ")");
    assembly.push_back("@0");
    assembly.push_back("D=A");
    assembly.push_back("(continue_" + std::to_string(m_routine) + ")");
    assembly.push_back("@SP");
    assembly.push_back("A=M-1");
    assembly.push_back("A=A-1");
    assembly.push_back("M=D");
    assembly.push_back("@SP");
    assembly.push_back("M=M-1");
    m_routine++;
}

void Rex::translateBinaryOp(Rex::instructionInfo insInfo, ASSEMBLY &assembly) {
    assembly.push_back("@SP");
    assembly.push_back("A=M-1");
    assembly.push_back("D=!M");
    if (insInfo.mnemonictype == MNEMONIC_NEG){
        assembly.push_back("D=D+1");
    }
    assembly.push_back("M=D");
}

void Rex::translateBinaryOp2(Rex::instructionInfo insInfo, ASSEMBLY &assembly) {
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
}

void Rex::translateGoTo(Rex::instructionInfo insInfo, ASSEMBLY &assembly) {

    if (insInfo.mnemonictype == MNEMONIC_IF_GO_TO){
        assembly.push_back("@SP");
        assembly.push_back("A=M-1");
        assembly.push_back("D=M");
        assembly.push_back("@SP");
        assembly.push_back("M=M-1");
        assembly.push_back("@" + insInfo.functionName);
        assembly.push_back("D;JNE");
        return;
    }

    assembly.push_back("@" + insInfo.functionName);
    assembly.push_back("0;JMP");

}

void Rex::translateCall(Rex::instructionInfo insInfo, ASSEMBLY &assembly) {
    std::string returnLabel = insInfo.functionName.substr(0, insInfo.functionName.find_first_of(".")) + "$return." + std::to_string(m_routine);
    std::vector<std::string> to_push = {{"@" + returnLabel}, {"local"}, {"argument"}, {"this"}, {"that"}};
    std::string instruction;
    instructionInfo temp_InsInfo;

    for (auto member: to_push){
        instruction = "push " + member;
        temp_InsInfo = getVMInsInfo(instruction, assembly);
        translatePush(temp_InsInfo, assembly);
    }

    assembly.push_back("// argument = SP - nArgs  - 5");
    assembly.push_back("@SP");
    assembly.push_back("D=M");
    assembly.push_back("@" + std::to_string(5 + std::stoi(insInfo.nArgs)));
    assembly.push_back("D=D-A");
    assembly.push_back("@" + m_constAddr["argument"]);
    assembly.push_back("M=D");

    // change local to point at SP
    assembly.push_back("// local = SP");
    assembly.push_back("@SP");
    assembly.push_back("D=M");
    assembly.push_back("@" + m_constAddr["local"]);
    assembly.push_back("M=D");

    assembly.push_back("@" + insInfo.functionName);
    assembly.push_back("0;JMP");

    assembly.push_back("(" + returnLabel + ")");
    m_returnLabel = returnLabel;
    m_routine++;
}

void Rex::translateLabel(Rex::instructionInfo insInfo, ASSEMBLY &assembly) {
    std::string label = insInfo.functionName;
    assembly.push_back("(" + label +")");
}

void Rex::to_lower(std::string &str) {
    std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) { return std::tolower(c); });
}

void Rex::translateReturn(Rex::instructionInfo insInfo, ASSEMBLY &assembly) {
    std::string instruction;
    instructionInfo temp_insInfo;

    std::vector<std::string> segments = {{"that"}, {"this"}, {"argument"}, {"local"}};
    int counter = 1;

    assembly.push_back("@" + m_constAddr["local"]);
    assembly.push_back("D=M");

    assembly.push_back("@endFrame");
    assembly.push_back("M=D");

//    5 is constant.
    assembly.push_back("@endFrame");
    assembly.push_back("D=M");
    assembly.push_back("@5");
    assembly.push_back("A=D-A");
    assembly.push_back("D=M");

    assembly.push_back("@retAddr" + std::to_string(m_routine));
    assembly.push_back("M=D");

    //   *ARG = POP()
    instruction = "pop argument 0";
    temp_insInfo = getVMInsInfo(instruction, assembly);
    translatePop(temp_insInfo, assembly);

    //  SP = ARG + 1
    assembly.push_back("@" + m_constAddr["argument"]);
    assembly.push_back("D=M+1");
    assembly.push_back("@SP");
    assembly.push_back("M=D");

    for (auto segment: segments) {
        assembly.push_back("@" + std::to_string(counter));
        assembly.push_back("D=A");

        assembly.push_back("@endFrame");
        assembly.push_back("A=M-D");
        assembly.push_back("D=M");

        assembly.push_back("@" + m_constAddr[segment]);
        assembly.push_back("M=D");
        counter++;
    }

    assembly.push_back("@retAddr" + std::to_string(m_routine));
    assembly.push_back("A=M");
    assembly.push_back("0;JMP");
    m_routine++;
}

void Rex::translateFunction(Rex::instructionInfo insInfo, ASSEMBLY &assembly) {
    std::string instruction;
    instructionInfo temp_InsInfo;

    instruction = "label " + insInfo.functionName;
    temp_InsInfo = getVMInsInfo(instruction, assembly);
    translateLabel(temp_InsInfo, assembly);

    for (int i = 0; i < std::stoi(insInfo.nArgs); i++) {
        instruction = "push constant 0";
        temp_InsInfo = getVMInsInfo(instruction, assembly);
        translatePush(temp_InsInfo, assembly);
    }
}
