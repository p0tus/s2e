#ifndef S2ETOOLS_STATIC_TRANSLATOR_H_

#define S2ETOOLS_STATIC_TRANSLATOR_H_

#include <ostream>
#include <fstream>

#include <lib/BinaryReaders/Library.h>
#include "CFG/CBasicBlock.h"

namespace s2etools
{

class InvalidAddressException {

};

class StaticTranslatorTool {
private:
    static bool s_translatorInited;
    BFDInterface *m_binary;

    //Outputs raw x86 translated code here
    std::ofstream *m_translatedCode;


    void translateBlockToX86_64(uint64_t address, void *buffer, int *codeSize);
    translator::CBasicBlock* translateBlockToLLVM(uint64_t address);

public:
    StaticTranslatorTool();
    ~StaticTranslatorTool();
    void translateToX86_64();
    void translateToLLVM();

};

}

#endif
