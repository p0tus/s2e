/*
 * LLVM backend for Tiny Code Generator for QEMU
 *
 * Copyright (c) 2010 Volodymyr Kuznetsov
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "tcg-llvm.h"

extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "disas.h"

#if defined(CONFIG_SOFTMMU)

#include "../../softmmu_defs.h"

static void *qemu_ld_helpers[5] = {
    (void*) __ldb_mmu,
    (void*) __ldw_mmu,
    (void*) __ldl_mmu,
    (void*) __ldq_mmu,
    (void*) __ldq_mmu,
};

static void *qemu_st_helpers[5] = {
    (void*) __stb_mmu,
    (void*) __stw_mmu,
    (void*) __stl_mmu,
    (void*) __stq_mmu,
    (void*) __stq_mmu,
};
#endif
}

#include <llvm/DerivedTypes.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/JITMemoryManager.h>
#include <llvm/ExecutionEngine/JIT.h>
#include <llvm/LLVMContext.h>
#include <llvm/Module.h>
#include <llvm/ModuleProvider.h>
#include <llvm/PassManager.h>
#include <llvm/Intrinsics.h>
#include <llvm/Analysis/Verifier.h>
#include <llvm/Target/TargetData.h>
#include <llvm/Target/TargetSelect.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Support/IRBuilder.h>

#include <iostream>
#include <sstream>

extern "C" {
    TranslationBlock *tcg_llvm_last_tb = 0;
    TCGLLVMTranslationBlock *tcg_llvm_last_llvm_tb = 0;
    uint64_t tcg_llvm_last_opc_index = 0;
    uint64_t tcg_llvm_last_pc = 0;

    uint64_t tcg_llvm_helper_call_addr;
    uint64_t tcg_llvm_helper_ret_addr;
    uint64_t tcg_llvm_helper_regs[3];

    void tcg_llvm_helper_wrapper(void);
}

using namespace llvm;

class TJITMemoryManager;

struct TCGLLVMTranslationBlock {
    TCGLLVMContext *tcgLLVMContext;
    Function *m_tbFunction;

    TCGLLVMTBFunctionPointer m_tbFunctionPointer;
    ptrdiff_t m_tbFunctionSize;
};

struct TCGLLVMContext {
    TCGContext* m_tcgContext;
    LLVMContext m_context;
    IRBuilder<> m_builder;

    /* Current m_module */
    Module *m_module;
    ModuleProvider *moduleProvider;

    /* Function for current translation block */
    Function *m_tbFunction;

    /* Current temp m_values */
    Value* m_values[TCG_MAX_TEMPS];

    /* Pointers to in-memory versions of globals or local temps */
    Value* m_memValuesPtr[TCG_MAX_TEMPS];

    /* For reg-based globals, store argument number,
     * for mem-based globals, store base value index */
    int m_globalsIdx[TCG_MAX_TEMPS];

    BasicBlock* m_labels[TCG_MAX_LABELS];

    /* Function pass manager (used for optimizing the code) */
    FunctionPassManager *m_functionPassManager;

    /* JIT engine */
    TJITMemoryManager *m_jitMemoryManager;
    ExecutionEngine *m_executionEngine;

    /* Count of generated translation blocks */
    int m_tbCount;

public:
    TCGLLVMContext(TCGContext* _tcgContext);
    ~TCGLLVMContext();

    /* Shortcuts */
    const Type* intType(int w) { return IntegerType::get(m_context, w); }
    const Type* intPtrType(int w) { return PointerType::get(intType(w), 0); }
    const Type* wordType() { return intType(TCG_TARGET_REG_BITS); }
    const Type* wordPtrType() { return intPtrType(TCG_TARGET_REG_BITS); }

    const Type* tcgType(int type) {
        return type == TCG_TYPE_I64 ? intType(64) : intType(32);
    }

    const Type* tcgPtrType(int type) {
        return type == TCG_TYPE_I64 ? intPtrType(64) : intPtrType(32);
    }

    /* Helpers */
    Value* getValue(int idx);
    void setValue(int idx, Value *v);
    void delValue(int idx);

    Value* getPtrForValue(int idx);
    void delPtrForValue(int idx);
    void initGlobalsAndLocalTemps();

    void invalidateCachedMemory();

    BasicBlock* getLabel(int idx);
    void delLabel(int idx);
    void startNewBasicBlock(BasicBlock *bb = NULL);

    Value* generateQemuMemOp(bool ld, Value* value, Value *addr,
                                int mem_index, int bits);

    /* Code generation */
    int generateOperation(int opc, const TCGArg *args);
    TCGLLVMTranslationBlock* generateCode();
};

/* Custom JITMemoryManager in order to capture the size of
 * the last generated function */
class TJITMemoryManager: public JITMemoryManager {
    JITMemoryManager* m_base;
    ptrdiff_t m_lastFunctionSize;
public:
    TJITMemoryManager():
        m_base(JITMemoryManager::CreateDefaultMemManager()),
        m_lastFunctionSize(0) {}
    ~TJITMemoryManager() { delete m_base; }

    ptrdiff_t getLastFunctionSize() const { return m_lastFunctionSize; }

    uint8_t *startFunctionBody(const Function *F, uintptr_t &ActualSize) {
        m_lastFunctionSize = 0;
        return m_base->startFunctionBody(F, ActualSize);
    }
    void endFunctionBody(const Function *F, uint8_t *FunctionStart,
                                uint8_t *FunctionEnd) {
        m_lastFunctionSize = FunctionEnd - FunctionStart;
        m_base->endFunctionBody(F, FunctionStart, FunctionEnd);
    }

    void setMemoryWritable() { m_base->setMemoryWritable(); }
    void setMemoryExecutable() { m_base->setMemoryExecutable(); }
    void setPoisonMemory(bool poison) { m_base->setPoisonMemory(poison); }
    void AllocateGOT() { m_base->AllocateGOT(); }
    uint8_t *getGOTBase() const { return m_base->getGOTBase(); }
    void SetDlsymTable(void *ptr) { m_base->SetDlsymTable(ptr); }
    void *getDlsymTable() const { return m_base->getDlsymTable(); }
    uint8_t *allocateStub(const GlobalValue* F, unsigned StubSize,
                                unsigned Alignment) {
        return m_base->allocateStub(F, StubSize, Alignment);
    }
    uint8_t *allocateSpace(intptr_t Size, unsigned Alignment) {
        return m_base->allocateSpace(Size, Alignment);
    }
    uint8_t *allocateGlobal(uintptr_t Size, unsigned Alignment) {
        return m_base->allocateGlobal(Size, Alignment);
    }
    void deallocateMemForFunction(const Function *F) {
        m_base->deallocateMemForFunction(F);
    }
    uint8_t* startExceptionTable(const Function* F, uintptr_t &ActualSize) {
        return m_base->startExceptionTable(F, ActualSize);
    }
    void endExceptionTable(const Function *F, uint8_t *TableStart,
                                 uint8_t *TableEnd, uint8_t* FrameRegister) {
        m_base->endExceptionTable(F, TableStart, TableEnd, FrameRegister);
    }
    bool CheckInvariants(std::string &ErrorStr) {
        return m_base->CheckInvariants(ErrorStr);
    }
    size_t GetDefaultCodeSlabSize() {
        return m_base->GetDefaultCodeSlabSize();
    }
    size_t GetDefaultDataSlabSize() {
        return m_base->GetDefaultDataSlabSize();
    }
    size_t GetDefaultStubSlabSize() {
        return m_base->GetDefaultStubSlabSize();
    }
    unsigned GetNumCodeSlabs() { return m_base->GetNumCodeSlabs(); }
    unsigned GetNumDataSlabs() { return m_base->GetNumDataSlabs(); }
    unsigned GetNumStubSlabs() { return m_base->GetNumStubSlabs(); }
};

TCGLLVMContext::TCGLLVMContext(TCGContext* _tcgContext)
    : m_tcgContext(_tcgContext), m_context(), m_builder(m_context),
      m_tbFunction(NULL), m_tbCount(0)
{
    std::memset(m_values, 0, sizeof(m_values));
    std::memset(m_memValuesPtr, 0, sizeof(m_memValuesPtr));
    std::memset(m_globalsIdx, 0, sizeof(m_globalsIdx));
    std::memset(m_labels, 0, sizeof(m_labels));

    InitializeNativeTarget();

    m_module = new Module("tcg-llvm", m_context);
    m_jitMemoryManager = new TJITMemoryManager();
    m_executionEngine = EngineBuilder(m_module)
        .setJITMemoryManager(m_jitMemoryManager)
        .create();
    assert(m_executionEngine != NULL);

    moduleProvider = new ExistingModuleProvider(m_module);
    m_functionPassManager = new FunctionPassManager(moduleProvider);
    m_functionPassManager->add(
            new TargetData(*m_executionEngine->getTargetData()));

    m_functionPassManager->add(createReassociatePass());
    m_functionPassManager->add(createConstantPropagationPass());
    m_functionPassManager->add(createInstructionCombiningPass());
    m_functionPassManager->add(createGVNPass());
    m_functionPassManager->add(createDeadStoreEliminationPass());
    m_functionPassManager->add(createCFGSimplificationPass());
    m_functionPassManager->add(createPromoteMemoryToRegisterPass());

    m_functionPassManager->doInitialization();
}

TCGLLVMContext::~TCGLLVMContext()
{
    delete m_functionPassManager;
    delete moduleProvider;

    // the following line will also delete
    // m_module and all its functions
    delete m_executionEngine;
}

Value* TCGLLVMContext::getPtrForValue(int idx)
{
    TCGContext *s = m_tcgContext;
    TCGTemp &temp = s->temps[idx];

    assert(idx < s->nb_globals || s->temps[idx].temp_local);
    
    if(m_memValuesPtr[idx] == NULL) {
        assert(idx < s->nb_globals);

        if(temp.fixed_reg) {
            Value *v = m_builder.CreateConstGEP1_32(
                    m_tbFunction->arg_begin(), m_globalsIdx[idx]);
            m_memValuesPtr[idx] = m_builder.CreatePointerCast(
                    v, tcgPtrType(temp.type)
#ifndef NDEBUG
                    , StringRef(temp.name) + "_ptr"
#endif
                    );

        } else {
            Value *v = getValue(m_globalsIdx[idx]);
            assert(v->getType() == wordType());

            v = m_builder.CreateAdd(v, ConstantInt::get(
                            wordType(), temp.mem_offset));
            m_memValuesPtr[idx] =
                m_builder.CreateIntToPtr(v, tcgPtrType(temp.type)
#ifndef NDEBUG
                        , StringRef(temp.name) + "_ptr"
#endif
                        );
        }
    }

    return m_memValuesPtr[idx];
}

inline void TCGLLVMContext::delValue(int idx)
{
    /* XXX
    if(m_values[idx] && m_values[idx]->use_empty()) {
        if(!isa<Instruction>(m_values[idx]) ||
                !cast<Instruction>(m_values[idx])->getParent())
            delete m_values[idx];
    }
    */
    m_values[idx] = NULL;
}

inline void TCGLLVMContext::delPtrForValue(int idx)
{
    /* XXX
    if(m_memValuesPtr[idx] && m_memValuesPtr[idx]->use_empty()) {
        if(!isa<Instruction>(m_memValuesPtr[idx]) ||
                !cast<Instruction>(m_memValuesPtr[idx])->getParent())
            delete m_memValuesPtr[idx];
    }
    */
    m_memValuesPtr[idx] = NULL;
}

Value* TCGLLVMContext::getValue(int idx)
{
    if(m_values[idx] == NULL) {
        if(idx < m_tcgContext->nb_globals) {
            m_values[idx] = m_builder.CreateLoad(getPtrForValue(idx)
#ifndef NDEBUG
                    , StringRef(m_tcgContext->temps[idx].name) + "_v"
#endif
                    );
        } else if(m_tcgContext->temps[idx].temp_local) {
            m_values[idx] = m_builder.CreateLoad(getPtrForValue(idx));
#ifndef NDEBUG
            std::ostringstream name;
            name << "loc" << (idx - m_tcgContext->nb_globals) << "_v";
            m_values[idx]->setName(name.str());
#endif
        } else {
            // Temp value was not previousely assigned
            assert(false); // XXX: or return zero constant ?
        }
    }

    return m_values[idx];
}

void TCGLLVMContext::setValue(int idx, Value *v)
{
    delValue(idx);
    m_values[idx] = v;

    if(!v->hasName() && !isa<Constant>(v)) {
#ifndef NDEBUG
        if(idx < m_tcgContext->nb_globals)
            v->setName(StringRef(m_tcgContext->temps[idx].name) + "_v");
        if(m_tcgContext->temps[idx].temp_local) {
            std::ostringstream name;
            name << "loc" << (idx - m_tcgContext->nb_globals) << "_v";
            v->setName(name.str());
        } else {
            std::ostringstream name;
            name << "tmp" << (idx - m_tcgContext->nb_globals) << "_v";
            v->setName(name.str());
        }
#endif
    }

    if(idx < m_tcgContext->nb_globals) {
        // We need to save a global copy of a value
        m_builder.CreateStore(v, getPtrForValue(idx));

        if(m_tcgContext->temps[idx].fixed_reg) {
            /* Invalidate all dependent global vals and pointers */
            for(int i=0; i<m_tcgContext->nb_globals; ++i) {
                if(i != idx && !m_tcgContext->temps[idx].fixed_reg &&
                                    m_globalsIdx[i] == idx) {
                    delValue(i);
                    delPtrForValue(i);
                }
            }
        }
    } else if(m_tcgContext->temps[idx].temp_local) {
        // We need to save an in-memory copy of a value
        m_builder.CreateStore(v, getPtrForValue(idx));
    }
}

void TCGLLVMContext::initGlobalsAndLocalTemps()
{
    TCGContext *s = m_tcgContext;

    int reg_to_idx[TCG_TARGET_NB_REGS];
    for(int i=0; i<TCG_TARGET_NB_REGS; ++i)
        reg_to_idx[i] = -1;

    int argNumber = 0;
    for(int i=0; i<s->nb_globals; ++i) {
        if(s->temps[i].fixed_reg) {
            // This global is in fixed host register. We are
            // mapping such registers to function arguments
            m_globalsIdx[i] = argNumber++;
            reg_to_idx[s->temps[i].reg] = i;

        } else {
            // This global is in memory at (mem_reg + mem_offset).
            // Base value is not known yet, so just store mem_reg
            m_globalsIdx[i] = s->temps[i].mem_reg;
        }
    }

    // Map mem_reg to index for memory-based globals
    for(int i=0; i<s->nb_globals; ++i) {
        if(!s->temps[i].fixed_reg) {
            assert(reg_to_idx[m_globalsIdx[i]] >= 0);
            m_globalsIdx[i] = reg_to_idx[m_globalsIdx[i]];
        }
    }

    // Allocate local temps
    for(int i=s->nb_globals; i<TCG_MAX_TEMPS; ++i) {
        if(s->temps[i].temp_local) {
            std::ostringstream pName;
            pName << "loc_" << (i - s->nb_globals) << "ptr";
            m_memValuesPtr[i] = m_builder.CreateAlloca(
                tcgType(s->temps[i].type), 0, pName.str());
        }
    }
}

inline BasicBlock* TCGLLVMContext::getLabel(int idx)
{
    if(!m_labels[idx]) {
        std::ostringstream bbName;
        bbName << "label_" << idx;
        m_labels[idx] = BasicBlock::Create(m_context, bbName.str());
    }
    return m_labels[idx];
}

inline void TCGLLVMContext::delLabel(int idx)
{
    /* XXX
    if(m_labels[idx] && m_labels[idx]->use_empty() &&
            !m_labels[idx]->getParent())
        delete m_labels[idx];
    */
    m_labels[idx] = NULL;
}

void TCGLLVMContext::startNewBasicBlock(BasicBlock *bb)
{
    if(!bb)
        bb = BasicBlock::Create(m_context);
    else
        assert(bb->getParent() == 0);

    if(!m_builder.GetInsertBlock()->getTerminator())
        m_builder.CreateBr(bb);

    m_tbFunction->getBasicBlockList().push_back(bb);
    m_builder.SetInsertPoint(bb);

    /* Invalidate all temps */
    for(int i=0; i<TCG_MAX_TEMPS; ++i)
        delValue(i);

    /* Invalidate all pointers to globals */
    for(int i=0; i<m_tcgContext->nb_globals; ++i)
        delPtrForValue(i);
}

Value* TCGLLVMContext::generateQemuMemOp(bool ld,
        Value *value, Value *addr, int mem_index, int bits)
{
    assert(addr->getType() == intType(TARGET_LONG_BITS));
    assert(ld || value->getType() == intType(bits));
    assert(TCG_TARGET_REG_BITS == 64); //XXX

#ifdef CONFIG_SOFTMMU

#define __x_offsetof(TYPE, MEMBER) ((size_t) &((TYPE *) 0)->MEMBER)

    BasicBlock *bb_1 = BasicBlock::Create(m_context);
    BasicBlock *bb_2 = BasicBlock::Create(m_context);
    BasicBlock *bb_m = BasicBlock::Create(m_context);

    Value *v, *v1, *v2;

    v = m_builder.CreateLShr(addr, ConstantInt::get(addr->getType(),
                (TARGET_PAGE_BITS - CPU_TLB_ENTRY_BITS)));
    v = m_builder.CreateAnd(v, ConstantInt::get(addr->getType(),
            ((CPU_TLB_SIZE - 1) << CPU_TLB_ENTRY_BITS)));

    assert(m_tcgContext->temps[0].reg == TCG_AREG0);
    assert(getValue(0)->getType() == wordType());
    v = m_builder.CreateAdd(
            m_builder.CreateZExt(v, wordType()),
            getValue(0)); // XXX

    v1 = m_builder.CreateAdd(v, ConstantInt::get(wordType(),
            ld ?
                __x_offsetof(CPUState, tlb_table[mem_index][0].addr_read) :
                __x_offsetof(CPUState, tlb_table[mem_index][0].addr_write)));

    v1 = m_builder.CreateLoad(
            m_builder.CreateIntToPtr(v1, intPtrType(TARGET_LONG_BITS)));

    v2 = m_builder.CreateAnd(addr, ConstantInt::get(addr->getType(),
            (TARGET_PAGE_MASK | ((bits>>3) - 1))));

    m_builder.CreateCondBr(m_builder.CreateICmpEQ(v1, v2), bb_1, bb_2);

    /* TLB miss: call qemu helper */
    m_tbFunction->getBasicBlockList().push_back(bb_2);
    m_builder.SetInsertPoint(bb_2);

    m_builder.CreateStore(
        ConstantInt::get(wordType(),
                ld ? (uint64_t) qemu_ld_helpers[bits>>4]:
                     (uint64_t) qemu_st_helpers[bits>>4]),
        m_builder.CreateIntToPtr(
            ConstantInt::get(wordType(),
                (uint64_t) &tcg_llvm_helper_call_addr),
            wordPtrType()));

    std::vector<Value*> argValues; argValues.reserve(3);
    argValues.push_back(addr);
    if(!ld)
        argValues.push_back(value);
    argValues.push_back(ConstantInt::get(intType(8*sizeof(int)), mem_index));

    std::vector<const Type*> argTypes; argTypes.reserve(3);
    for(int i=0; i<(ld?2:3); ++i)
        argTypes.push_back(argValues[i]->getType());

    Value* funcAddr = m_builder.CreateIntToPtr(
            ConstantInt::get(wordType(), (uint64_t) tcg_llvm_helper_wrapper),
            PointerType::get(FunctionType::get(
                    ld ? intType(bits) : Type::getVoidTy(m_context),
                    argTypes, false), 0));
    v2 = m_builder.CreateCall(funcAddr, argValues.begin(), argValues.end());

    m_builder.CreateBr(bb_m);

    /* TLB hit: load or store value directly */
    m_tbFunction->getBasicBlockList().push_back(bb_1);
    m_builder.SetInsertPoint(bb_1);

    v = m_builder.CreateAdd(v, ConstantInt::get(wordType(),
            __x_offsetof(CPUState, tlb_table[mem_index][0].addend)));
    v1 = m_builder.CreateLoad(
            m_builder.CreateIntToPtr(v,
                intPtrType(8*sizeof(target_phys_addr_t))));
    addr = m_builder.CreateAdd(
            m_builder.CreateZExt(addr, wordType()),
            m_builder.CreateZExt(v1, wordType()));
    addr = m_builder.CreateIntToPtr(addr, intPtrType(bits));

    if(ld)
        v1 = m_builder.CreateLoad(addr);
    else
        m_builder.CreateStore(value, addr);

    m_builder.CreateBr(bb_m);

    /* end */
    m_tbFunction->getBasicBlockList().push_back(bb_m);
    m_builder.SetInsertPoint(bb_m);

    if(ld) {
        PHINode *phi = m_builder.CreatePHI(intType(bits));
        phi->addIncoming(v1, bb_1);
        phi->addIncoming(v2, bb_2);
        return phi;
    } else {
        return NULL;
    }

#undef __x_offsetof

#else
    addr = m_builder.CreateZExt(addr, wordType());
    addr = m_builder.CreateAdd(addr,
        ConstantInt::get(wordType(), GUEST_BASE));
    addr = m_builder.CreateIntToPtr(addr, intPtrType(bits));
    if(ld) {
        return m_builder.CreateLoad(addr);
    } else {
        m_builder.CreateStore(value, addr);
        return NULL;
    }
#endif
}

int TCGLLVMContext::generateOperation(int opc, const TCGArg *args)
{
    Value *v;
    TCGOpDef &def = tcg_op_defs[opc];
    int nb_args = def.nb_args;

    switch(opc) {
    case INDEX_op_debug_insn_start:
        break;

    /* predefined ops */
    case INDEX_op_nop:
    case INDEX_op_nop1:
    case INDEX_op_nop2:
    case INDEX_op_nop3:
        break;

    case INDEX_op_nopn:
        nb_args = args[0];
        break;

    case INDEX_op_discard:
        delValue(args[0]);
        break;

    case INDEX_op_call:
        {
            int nb_oargs = args[0] >> 16;
            int nb_iargs = args[0] & 0xffff;
            nb_args = nb_oargs + nb_iargs + def.nb_cargs + 1;

            int flags = args[nb_oargs + nb_iargs + 1];
            assert((flags & TCG_CALL_TYPE_MASK) == TCG_CALL_TYPE_STD);

            std::vector<Value*> argValues;
            std::vector<const Type*> argTypes;
            argValues.reserve(nb_iargs-1);
            argTypes.reserve(nb_iargs-1);
            for(int i=0; i < nb_iargs-1; ++i) {
                TCGArg arg = args[nb_oargs + i + 1];
                if(arg != TCG_CALL_DUMMY_ARG) {
                    Value *v = getValue(arg);
                    argValues.push_back(v);
                    argTypes.push_back(v->getType());
                }
            }

            assert(nb_oargs == 0 || nb_oargs == 1);
            const Type* retType = nb_oargs == 0 ?
                Type::getVoidTy(m_context) : wordType(); // XXX?

            Value* funcAddr = getValue(args[nb_oargs + nb_iargs]);
            m_builder.CreateStore(funcAddr, m_builder.CreateIntToPtr(
                        ConstantInt::get(wordType(),
                            (uint64_t) &tcg_llvm_helper_call_addr),
                        wordPtrType()));

            funcAddr = m_builder.CreateIntToPtr(
                    ConstantInt::get(wordType(), (uint64_t) tcg_llvm_helper_wrapper),
                    PointerType::get(
                        FunctionType::get(retType, argTypes, false), 0));

            Value* result = m_builder.CreateCall(funcAddr,
                                argValues.begin(), argValues.end());

            /* Invalidate in-memory values because
             * function might have changed them */
            for(int i=0; i<m_tcgContext->nb_globals; ++i)
                delValue(i);

            for(int i=m_tcgContext->nb_globals; i<TCG_MAX_TEMPS; ++i)
                if(m_tcgContext->temps[i].temp_local)
                    delValue(i);

            /* Invalidate all pointers to globals */
            for(int i=0; i<m_tcgContext->nb_globals; ++i)
                delPtrForValue(i);

            if(nb_oargs == 1)
                setValue(args[1], result);
        }
        break;

    case INDEX_op_br:
        m_builder.CreateBr(getLabel(args[0]));
        startNewBasicBlock();
        break;

#define __OP_BRCOND_C(tcg_cond, cond)                               \
            case tcg_cond:                                          \
                v = m_builder.CreateICmp ## cond(                   \
                        getValue(args[0]), getValue(args[1]));      \
            break;

#define __OP_BRCOND(opc_name, bits)                                 \
    case opc_name: {                                                \
        assert(getValue(args[0])->getType() == intType(bits));      \
        assert(getValue(args[1])->getType() == intType(bits));      \
        switch(args[2]) {                                           \
            __OP_BRCOND_C(TCG_COND_EQ,   EQ)                        \
            __OP_BRCOND_C(TCG_COND_NE,   NE)                        \
            __OP_BRCOND_C(TCG_COND_LT,  SLT)                        \
            __OP_BRCOND_C(TCG_COND_GE,  SGE)                        \
            __OP_BRCOND_C(TCG_COND_LE,  SLE)                        \
            __OP_BRCOND_C(TCG_COND_GT,  SGT)                        \
            __OP_BRCOND_C(TCG_COND_LTU, ULT)                        \
            __OP_BRCOND_C(TCG_COND_GEU, UGE)                        \
            __OP_BRCOND_C(TCG_COND_LEU, ULE)                        \
            __OP_BRCOND_C(TCG_COND_GTU, UGT)                        \
            default:                                                \
                tcg_abort();                                        \
        }                                                           \
        BasicBlock* bb = BasicBlock::Create(m_context);             \
        m_builder.CreateCondBr(v, getLabel(args[3]), bb);           \
        startNewBasicBlock(bb);                                     \
    } break;

    __OP_BRCOND(INDEX_op_brcond_i32, 32)

#if TCG_TARGET_REG_BITS == 64
    __OP_BRCOND(INDEX_op_brcond_i64, 64)
#endif

#undef __OP_BRCOND_C
#undef __OP_BRCOND

    case INDEX_op_set_label:
        assert(getLabel(args[0])->getParent() == 0);
        startNewBasicBlock(getLabel(args[0]));
        break;

    case INDEX_op_movi_i32:
        setValue(args[0], ConstantInt::get(intType(32), args[1]));
        break;

    case INDEX_op_mov_i32:
        // Move operation may perform truncation of the value
        assert(getValue(args[1])->getType() == intType(32) ||
                getValue(args[1])->getType() == intType(64));
        setValue(args[0],
                m_builder.CreateTrunc(getValue(args[1]), intType(32)));
        break;

#if TCG_TARGET_REG_BITS == 64
    case INDEX_op_movi_i64:
        setValue(args[0], ConstantInt::get(intType(64), args[1]));
        break;

    case INDEX_op_mov_i64:
        assert(getValue(args[1])->getType() == intType(64));
        setValue(args[0], getValue(args[1]));
        break;
#endif

    /* size extensions */
#define __EXT_OP(opc_name, truncBits, opBits, signE )               \
    case opc_name:                                                  \
        /*                                                          \
        assert(getValue(args[1])->getType() == intType(opBits) ||   \
               getValue(args[1])->getType() == intType(truncBits)); \
        */                                                          \
        setValue(args[0], m_builder.Create ## signE ## Ext(         \
                m_builder.CreateTrunc(                              \
                    getValue(args[1]), intType(truncBits)),         \
                intType(opBits)));                                  \
        break;

    __EXT_OP(INDEX_op_ext8s_i32,   8, 32, S)
    __EXT_OP(INDEX_op_ext8u_i32,   8, 32, Z)
    __EXT_OP(INDEX_op_ext16s_i32, 16, 32, S)
    __EXT_OP(INDEX_op_ext16u_i32, 16, 32, Z)

#if TCG_TARGET_REG_BITS == 64
    __EXT_OP(INDEX_op_ext8s_i64,   8, 64, S)
    __EXT_OP(INDEX_op_ext8u_i64,   8, 64, Z)
    __EXT_OP(INDEX_op_ext16s_i64, 16, 64, S)
    __EXT_OP(INDEX_op_ext16u_i64, 16, 64, Z)
    __EXT_OP(INDEX_op_ext32s_i64, 32, 64, S)
    __EXT_OP(INDEX_op_ext32u_i64, 32, 64, Z)
#endif

#undef __EXT_OP

    /* load/store */
#define __LD_OP(opc_name, memBits, regBits, signE)                  \
    case opc_name:                                                  \
        assert(getValue(args[1])->getType() == wordType());         \
        v = m_builder.CreateAdd(getValue(args[1]),                  \
                    ConstantInt::get(wordType(), args[2]));         \
        v = m_builder.CreateIntToPtr(v, intPtrType(memBits));       \
        v = m_builder.CreateLoad(v);                                \
        setValue(args[0], m_builder.Create ## signE ## Ext(         \
                    v, intType(regBits)));                          \
        break;

#define __ST_OP(opc_name, memBits, regBits)                         \
    case opc_name:                                                  \
        assert(getValue(args[0])->getType() == intType(regBits));   \
        assert(getValue(args[1])->getType() == wordType());         \
        v = m_builder.CreateAdd(getValue(args[1]),                  \
                    ConstantInt::get(wordType(), args[2]));         \
        v = m_builder.CreateIntToPtr(v, intPtrType(memBits));       \
        m_builder.CreateStore(m_builder.CreateTrunc(                \
                getValue(args[0]), intType(memBits)), v);           \
        break;

    __LD_OP(INDEX_op_ld8u_i32,   8, 32, Z)
    __LD_OP(INDEX_op_ld8s_i32,   8, 32, S)
    __LD_OP(INDEX_op_ld16u_i32, 16, 32, Z)
    __LD_OP(INDEX_op_ld16s_i32, 16, 32, S)
    __LD_OP(INDEX_op_ld_i32,    32, 32, Z)

    __ST_OP(INDEX_op_st8_i32,   8, 32)
    __ST_OP(INDEX_op_st16_i32, 16, 32)
    __ST_OP(INDEX_op_st_i32,   32, 32)

#if TCG_TARGET_REG_BITS == 64
    __LD_OP(INDEX_op_ld8u_i64,   8, 64, Z)
    __LD_OP(INDEX_op_ld8s_i64,   8, 64, S)
    __LD_OP(INDEX_op_ld16u_i64, 16, 64, Z)
    __LD_OP(INDEX_op_ld16s_i64, 16, 64, S)
    __LD_OP(INDEX_op_ld32u_i64, 32, 64, Z)
    __LD_OP(INDEX_op_ld32s_i64, 32, 64, S)
    __LD_OP(INDEX_op_ld_i64,    64, 64, Z)

    __ST_OP(INDEX_op_st8_i64,   8, 64)
    __ST_OP(INDEX_op_st16_i64, 16, 64)
    __ST_OP(INDEX_op_st32_i64, 32, 64)
    __ST_OP(INDEX_op_st_i64,   64, 64)
#endif

#undef __LD_OP
#undef __ST_OP

    /* arith */
#define __ARITH_OP(opc_name, op, bits)                              \
    case opc_name:                                                  \
        assert(getValue(args[1])->getType() == intType(bits));      \
        assert(getValue(args[2])->getType() == intType(bits));      \
        setValue(args[0], m_builder.Create ## op(                   \
                getValue(args[1]), getValue(args[2])));             \
        break;

#define __ARITH_OP_DIV2(opc_name, signE, bits)                      \
    case opc_name:                                                  \
        assert(getValue(args[2])->getType() == intType(bits));      \
        assert(getValue(args[3])->getType() == intType(bits));      \
        assert(getValue(args[4])->getType() == intType(bits));      \
        v = m_builder.CreateShl(                                    \
                m_builder.CreateZExt(                               \
                    getValue(args[3]), intType(bits*2)),            \
                m_builder.CreateZExt(                               \
                    ConstantInt::get(intType(bits), bits),          \
                    intType(bits*2)));                              \
        v = m_builder.CreateOr(v,                                   \
                m_builder.CreateZExt(                               \
                    getValue(args[2]), intType(bits*2)));           \
        setValue(args[0], m_builder.Create ## signE ## Div(         \
                v, getValue(args[4])));                             \
        setValue(args[1], m_builder.Create ## signE ## Rem(         \
                v, getValue(args[4])));                             \
        break;

#define __ARITH_OP_ROT(opc_name, op1, op2, bits)                    \
    case opc_name:                                                  \
        assert(getValue(args[1])->getType() == intType(bits));      \
        assert(getValue(args[2])->getType() == intType(bits));      \
        v = m_builder.CreateSub(                                    \
                ConstantInt::get(intType(bits), bits),              \
                getValue(args[2]));                                 \
        setValue(args[0], m_builder.CreateOr(                       \
                m_builder.Create ## op1 (                           \
                    getValue(args[1]), getValue(args[2])),          \
                m_builder.Create ## op2 (                           \
                    getValue(args[1]), v)));                        \
        break;

#define __ARITH_OP_I(opc_name, op, i, bits)                         \
    case opc_name:                                                  \
        assert(getValue(args[1])->getType() == intType(bits));      \
        setValue(args[0], m_builder.Create ## op(                   \
                    ConstantInt::get(intType(bits), i),             \
                    getValue(args[1])));                            \
        break;

#define __ARITH_OP_BSWAP(opc_name, sBits, bits)                     \
    case opc_name: {                                                \
        assert(getValue(args[1])->getType() == intType(bits));      \
        const Type* Tys[] = { intType(sBits) };                     \
        Function *bswap = Intrinsic::getDeclaration(m_module,       \
                Intrinsic::bswap, Tys, 1);                          \
        v = m_builder.CreateTrunc(getValue(args[1]),intType(sBits));\
        setValue(args[0], m_builder.CreateZExt(                     \
                m_builder.CreateCall(bswap, v), intType(bits)));    \
        } break;


    __ARITH_OP(INDEX_op_add_i32, Add, 32)
    __ARITH_OP(INDEX_op_sub_i32, Sub, 32)
    __ARITH_OP(INDEX_op_mul_i32, Mul, 32)

#ifdef TCG_TARGET_HAS_div_i32
    __ARITH_OP(INDEX_op_div_i32,  SDiv, 32)
    __ARITH_OP(INDEX_op_divu_i32, UDiv, 32)
    __ARITH_OP(INDEX_op_rem_i32,  SRem, 32)
    __ARITH_OP(INDEX_op_remu_i32, URem, 32)
#else
    __ARITH_OP_DIV2(INDEX_op_div2_i32,  S, 32)
    __ARITH_OP_DIV2(INDEX_op_divu2_i32, U, 32)
#endif

    __ARITH_OP(INDEX_op_and_i32, And, 32)
    __ARITH_OP(INDEX_op_or_i32,   Or, 32)
    __ARITH_OP(INDEX_op_xor_i32, Xor, 32)

    __ARITH_OP(INDEX_op_shl_i32,  Shl, 32)
    __ARITH_OP(INDEX_op_shr_i32, LShr, 32)
    __ARITH_OP(INDEX_op_sar_i32, AShr, 32)

    __ARITH_OP_ROT(INDEX_op_rotl_i32, Shl, LShr, 32)
    __ARITH_OP_ROT(INDEX_op_rotr_i32, LShr, Shl, 32)

    __ARITH_OP_I(INDEX_op_not_i32, Xor, (uint64_t) -1, 32)
    __ARITH_OP_I(INDEX_op_neg_i32, Sub, 0, 32)

    __ARITH_OP_BSWAP(INDEX_op_bswap16_i32, 16, 32)
    __ARITH_OP_BSWAP(INDEX_op_bswap32_i32, 32, 32)

#if TCG_TARGET_REG_BITS == 64
    __ARITH_OP(INDEX_op_add_i64, Add, 64)
    __ARITH_OP(INDEX_op_sub_i64, Sub, 64)
    __ARITH_OP(INDEX_op_mul_i64, Mul, 64)

#ifdef TCG_TARGET_HAS_div_i64
    __ARITH_OP(INDEX_op_div_i64,  SDiv, 64)
    __ARITH_OP(INDEX_op_divu_i64, UDiv, 64)
    __ARITH_OP(INDEX_op_rem_i64,  SRem, 64)
    __ARITH_OP(INDEX_op_remu_i64, URem, 64)
#else
    __ARITH_OP_DIV2(INDEX_op_div2_i64,  S, 64)
    __ARITH_OP_DIV2(INDEX_op_divu2_i64, U, 64)
#endif

    __ARITH_OP(INDEX_op_and_i64, And, 64)
    __ARITH_OP(INDEX_op_or_i64,   Or, 64)
    __ARITH_OP(INDEX_op_xor_i64, Xor, 64)

    __ARITH_OP(INDEX_op_shl_i64,  Shl, 64)
    __ARITH_OP(INDEX_op_shr_i64, LShr, 64)
    __ARITH_OP(INDEX_op_sar_i64, AShr, 64)

    __ARITH_OP_ROT(INDEX_op_rotl_i64, Shl, LShr, 64)
    __ARITH_OP_ROT(INDEX_op_rotr_i64, LShr, Shl, 64)

    __ARITH_OP_I(INDEX_op_not_i64, Xor, (uint64_t) -1, 64)
    __ARITH_OP_I(INDEX_op_neg_i64, Sub, 0, 64)

    __ARITH_OP_BSWAP(INDEX_op_bswap16_i64, 16, 64)
    __ARITH_OP_BSWAP(INDEX_op_bswap32_i64, 32, 64)
    __ARITH_OP_BSWAP(INDEX_op_bswap64_i64, 64, 64)
#endif

#undef __ARITH_OP_BSWAP
#undef __ARITH_OP_I
#undef __ARITH_OP_ROT
#undef __ARITH_OP_DIV2
#undef __ARITH_OP

    /* QEMU specific */
#if TCG_TARGET_REG_BITS == 64

#define __OP_QEMU_ST(opc_name, bits)                                \
    case opc_name:                                                  \
        generateQemuMemOp(false,                                    \
            m_builder.CreateIntCast(                                \
                getValue(args[0]), intType(bits), false),           \
            getValue(args[1]), args[2], bits);                      \
        break;

#define __OP_QEMU_LD(opc_name, bits, signE)                         \
    case opc_name:                                                  \
        v = generateQemuMemOp(true, NULL,                           \
            getValue(args[1]), args[2], bits);                      \
        setValue(args[0], m_builder.Create ## signE ## Ext(         \
            v, intType(std::max(TARGET_LONG_BITS, bits))));         \
        break;

    __OP_QEMU_ST(INDEX_op_qemu_st8,   8)
    __OP_QEMU_ST(INDEX_op_qemu_st16, 16)
    __OP_QEMU_ST(INDEX_op_qemu_st32, 32)
    __OP_QEMU_ST(INDEX_op_qemu_st64, 64)

    __OP_QEMU_LD(INDEX_op_qemu_ld8s,   8, S)
    __OP_QEMU_LD(INDEX_op_qemu_ld8u,   8, Z)
    __OP_QEMU_LD(INDEX_op_qemu_ld16s, 16, S)
    __OP_QEMU_LD(INDEX_op_qemu_ld16u, 16, Z)
    __OP_QEMU_LD(INDEX_op_qemu_ld32s, 32, S)
    __OP_QEMU_LD(INDEX_op_qemu_ld32u, 32, Z)
    __OP_QEMU_LD(INDEX_op_qemu_ld64,  64, Z)

#undef __OP_QEMU_LD
#undef __OP_QEMU_ST

#endif

    case INDEX_op_exit_tb:
        m_builder.CreateRet(ConstantInt::get(wordType(), args[0]));
        break;

    case INDEX_op_goto_tb:
        /* XXX */
        break;

    default:
        std::cerr << "ERROR: unknown TCG micro operation '"
                  << def.name << "'" << std::endl;
        tcg_abort();
        break;
    }

    return nb_args;
}

TCGLLVMTranslationBlock* TCGLLVMContext::generateCode()
{
    /* Create new function for current translation block */
    std::ostringstream fName;
    fName << "tcg-llvm-tb-" << (m_tbCount++);

    /*
    if(m_tbFunction)
        m_tbFunction->eraseFromParent();
    */

    FunctionType *tbFunctionType = FunctionType::get(
            wordType(),
            std::vector<const Type*>(1, intPtrType(64)), false);
    m_tbFunction = Function::Create(tbFunctionType,
            Function::PrivateLinkage, fName.str(), m_module);
    BasicBlock *basicBlock = BasicBlock::Create(m_context,
            "entry", m_tbFunction);
    m_builder.SetInsertPoint(basicBlock);

    /* Prepare globals and temps information */
    initGlobalsAndLocalTemps();

    /* Generate code for each opc */
    const TCGArg *args = gen_opparam_buf;
    for(int opc_index=0; ;++opc_index) {
        int opc = gen_opc_buf[opc_index];

        if(opc == INDEX_op_end)
            break;

        if(opc == INDEX_op_debug_insn_start) {
            // volatile store of current OPC index
            m_builder.CreateStore(ConstantInt::get(wordType(), opc_index),
                m_builder.CreateIntToPtr(
                    ConstantInt::get(wordType(),
                        (uint64_t) &tcg_llvm_last_opc_index),
                    wordPtrType()),
                true);
            // volatile store of current PC
            m_builder.CreateStore(ConstantInt::get(wordType(), args[0]),
                m_builder.CreateIntToPtr(
                    ConstantInt::get(wordType(),
                        (uint64_t) &tcg_llvm_last_pc),
                    wordPtrType()),
                true);
        }

        args += generateOperation(opc, args);
    }

    /* Finalize function */
    if(!isa<ReturnInst>(m_tbFunction->back().back()))
        m_builder.CreateRet(ConstantInt::get(wordType(), 0));

    /* Clean up unused m_values */
    for(int i=0; i<TCG_MAX_TEMPS; ++i)
        delValue(i);

    /* Delete pointers after deleting values */
    for(int i=0; i<TCG_MAX_TEMPS; ++i)
        delPtrForValue(i);

    for(int i=0; i<TCG_MAX_LABELS; ++i)
        delLabel(i);

#ifndef NDEBUG
    verifyFunction(*m_tbFunction);
#endif

    m_functionPassManager->run(*m_tbFunction);

    TCGLLVMTranslationBlock *llvm_tb = new TCGLLVMTranslationBlock;
    llvm_tb->m_tbFunction = m_tbFunction;
    llvm_tb->m_tbFunctionPointer = (TCGLLVMTBFunctionPointer) 
        m_executionEngine->getPointerToFunction(m_tbFunction);
    llvm_tb->m_tbFunctionSize = m_jitMemoryManager->getLastFunctionSize();

    if(qemu_loglevel_mask(CPU_LOG_LLVM_IR)) {
        std::ostringstream s;
        s << *m_tbFunction;
        qemu_log("OUT (LLVM IR):\n");
        qemu_log("%s", s.str().c_str());
        qemu_log("\n");
        qemu_log_flush();
    }

    return llvm_tb;
}

TCGLLVMContext* tcg_llvm_context_new(TCGContext *s)
{
    return new TCGLLVMContext(s);
}

void tcg_llvm_context_free(TCGLLVMContext *l)
{
    delete l;
}

void tcg_llvm_gen_code(TCGLLVMContext *l, TranslationBlock *tb)
{
    assert(tb->llvm_tb == NULL);
    tb->llvm_tb = l->generateCode();
    tb->llvm_tc_ptr = (uint8_t*) tb->llvm_tb->m_tbFunctionPointer;
    tb->llvm_tc_end = tb->llvm_tc_ptr + tb->llvm_tb->m_tbFunctionSize;
}

void tcg_llvm_tb_alloc(TranslationBlock *tb)
{
    tb->llvm_tb = NULL;
}

void tcg_llvm_tb_free(TranslationBlock *tb)
{
    /*
    if(tb->llvm_tb) {
        tb->llvm_tb->m_tbFunction->eraseFromParent();
        delete tb->llvm_tb;
    }
    */
}

int tcg_llvm_search_last_pc(TranslationBlock *tb, uintptr_t searched_pc)
{
    assert(tb->llvm_tb && tb->llvm_tb == tcg_llvm_last_llvm_tb);
    return tcg_llvm_last_opc_index;
}

const char* tcg_llvm_get_func_name(TranslationBlock *tb)
{
    assert(tb->llvm_tb);
    return tb->llvm_tb->m_tbFunction->getNameStr().c_str();
}

uintptr_t tcg_llvm_qemu_tb_exec(TranslationBlock *tb,
                            void* volatile* saved_AREGs)
{
    tcg_llvm_last_tb = tb;
    tcg_llvm_last_llvm_tb = tb->llvm_tb;
    return tb->llvm_tb->m_tbFunctionPointer(saved_AREGs);
}
