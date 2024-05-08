#include <iostream>
#include <algorithm> 
#include <vector>
#include <string>
#include <intrin.h>

struct CPUFeature {
    int function_id;
    char reg;
    int bit;
    std::string description;
};

class CPUFeaturesChecker {
private:
    std::vector<std::string> _supportedFeatures;
    std::vector<std::string> _unsupportedFeatures;

    void checkFeature(const CPUFeature& feature) {
        int cpuInfo[4] = { 0 };
        __cpuid(cpuInfo, feature.function_id);
        int reg_value = 0;

        switch (feature.reg) {
        case 'a': reg_value = cpuInfo[0]; break;
        case 'b': reg_value = cpuInfo[1]; break;
        case 'c': reg_value = cpuInfo[2]; break;
        case 'd': reg_value = cpuInfo[3]; break;
        }

        if (reg_value & (1 << feature.bit)) {
            _supportedFeatures.push_back(feature.description);
        }
        else {
            _unsupportedFeatures.push_back(feature.description);
        }
    }

public:
    void checkCPUFeatures(const std::vector<CPUFeature>& features) {
        for (auto& feature : features) {
            checkFeature(feature);
        }
    }

    void printSupportedFeatures() {
        std::sort(_supportedFeatures.begin(), _supportedFeatures.end());

        std::cout << "***Supported Features:" << std::endl;
        for (const auto& feature : _supportedFeatures) {
            std::cout << feature << std::endl;
        }
    }

    void printUnsupportedFeatures() {
        std::sort(_unsupportedFeatures.begin(), _unsupportedFeatures.end());

        std::cout << "\n***Unsupported Features:" << std::endl;
        for (const auto& feature : _unsupportedFeatures) {
            std::cout << feature << std::endl;
        }
    }
};

int main() {
    std::vector<CPUFeature> features = {
        {1, 'd', 0, "FPU (Floating Point Unit)"},
        {1, 'd', 1, "VME (Virtual 8086 Mode Enhancements)"},
        {1, 'd', 2, "DE (Debugging Extensions)"},
        {1, 'd', 3, "PSE (Page Size Extension)"},
        {1, 'd', 4, "TSC (Time Stamp Counter)"},
        {1, 'd', 5, "MSR (Model Specific Registers)"},
        {1, 'd', 6, "PAE (Physical Address Extension)"},
        {1, 'd', 7, "MCE (Machine Check Exception)"},
        {1, 'd', 8, "CX8 (CMPXCHG8 Instruction)"},
        {1, 'd', 9, "APIC (On-chip APIC Hardware)"},
        {1, 'd', 11, "SEP (SYSENTER and SYSEXIT)"},
        {1, 'd', 13, "PGE (Page Global Enable)"},
        {1, 'd', 14, "MCA (Machine Check Architecture)"},
        {1, 'd', 15, "CMOV (Conditional Move Instructions)"},
        {1, 'd', 16, "PAT (Page Attribute Table)"},
        {1, 'd', 17, "PSE-36 (36-bit Page Size Extension)"},
        {1, 'd', 19, "CLFLUSH (CLFLUSH Instruction)"},
        {1, 'd', 23, "MMX (Multimedia Extensions)"},
        {1, 'd', 24, "FXSR (FXSAVE and FXSTOR Instructions)"},
        {1, 'd', 25, "SSE (Streaming SIMD Extensions)"},
        {1, 'd', 26, "SSE2 (Streaming SIMD Extensions 2)"},
        {1, 'd', 27, "SS (Self-Snoop)"},
        {1, 'd', 28, "HTT (Hyper-Threading Technology)"},
        {1, 'd', 29, "TM (Thermal Monitor supported)"},
        {1, 'd', 30, "IA64 (Itanium Processor)"},
        {1, 'd', 31, "PBE (Pending Break Enable)"},

        // Features from Function 0x01, ECX register
        {1, 'c', 0, "SSE3 (Streaming SIMD Extensions 3)"},
        {1, 'c', 1, "PCLMULQDQ (Carry-less Multiplication)"},
        {1, 'c', 2, "DTES64 (64-bit DS Area)"},
        {1, 'c', 3, "MONITOR (MONITOR/MWAIT)"},
        {1, 'c', 4, "DS-CPL (CPL Qualified Debug Store)"},
        {1, 'c', 5, "VMX (Virtual Machine Extensions)"},
        {1, 'c', 6, "SMX (Safer Mode Extensions)"},
        {1, 'c', 7, "EIST (Enhanced Intel SpeedStep Technology)"},
        {1, 'c', 8, "TM2 (Thermal Monitor 2)"},
        {1, 'c', 9, "SSSE3 (Supplemental SSE3 Instructions)"},
        {1, 'c', 10, "CNXT-ID (L1 Context ID)"},
        {1, 'c', 11, "SDBG (Silicon Debug Interface)"},
        {1, 'c', 12, "FMA (Fused Multiply Add)"},
        {1, 'c', 13, "CMPXCHG16B (Compare Exchange 16 Bytes)"},
        {1, 'c', 14, "xTPR Update Control"},
        {1, 'c', 15, "PDCM (Perfmon and Debug Capability)"},
        {1, 'c', 17, "PCID (Process-context identifiers)"},
        {1, 'c', 18, "DCA (Direct Cache Access)"},
        {1, 'c', 19, "SSE4.1 (Streaming SIMD Extensions 4.1)"},
        {1, 'c', 20, "SSE4.2 (Streaming SIMD Extensions 4.2)"},
        {1, 'c', 21, "x2APIC (Extended xAPIC Support)"},
        {1, 'c', 22, "MOVBE (Move Data After Swapping Bytes)"},
        {1, 'c', 23, "POPCNT (Population Count)"},
        {1, 'c', 24, "TSC-Deadline (Time Stamp Counter Deadline)"},
        {1, 'c', 25, "AES (AES Instruction Set)"},
        {1, 'c', 26, "XSAVE (XSAVE, XRSTOR, XSETBV, XGETBV)"},
        {1, 'c', 27, "OSXSAVE (OS-Enabled Extended State Management)"},
        {1, 'c', 28, "AVX (Advanced Vector Extensions)"},
        {1, 'c', 29, "F16C (16-bit Floating-Point Conversion)"},
        {1, 'c', 30, "RDRAND (RDRAND Instruction)"},
        {1, 'c', 31, "Hypervisor (Running on a Hypervisor)"},

        // Features from Function 0x07, EBX register
        {7, 'b', 0, "FSGSBASE (Access to base of %fs and %gs)"},
        {7, 'b', 1, "IA32_TSC_ADJUST (TSC Adjustment MSR 0x3B)"},
        {7, 'b', 2, "SGX (Software Guard Extensions)"},
        {7, 'b', 3, "BMI1 (Bit Manipulation Instruction Set 1)"},
        {7, 'b', 4, "HLE (Hardware Lock Elision)"},
        {7, 'b', 5, "AVX2 (Advanced Vector Extensions 2)"},
        {7, 'b', 6, "FDPEXONLY (FDP Exception Only)"},
        {7, 'b', 7, "SMEP (Supervisor Mode Execution Prevention)"},
        {7, 'b', 8, "BMI2 (Bit Manipulation Instruction Set 2)"},
        {7, 'b', 9, "ERMS (Enhanced REP MOVSB/STOSB)"},
        {7, 'b', 10, "INVPCID (Invalidate Process-Context Identifier)"},
        {7, 'b', 11, "RTM (Restricted Transactional Memory)"},
        {7, 'b', 12, "PQM (Platform Quality of Service Monitoring)"},
        {7, 'b', 13, "FPU CS and FPU DS Deprecated"},
        {7, 'b', 14, "MPX (Memory Protection Extensions)"},
        {7, 'b', 15, "PQE (Platform Quality of Service Enforcement)"},
        {7, 'b', 16, "AVX512F (AVX-512 Foundation)"},
        {7, 'b', 17, "AVX512DQ (AVX-512 Doubleword and Quadword Instructions)"},
        {7, 'b', 18, "RDSEED (RDSEED Instruction)"},
        {7, 'b', 19, "ADX (Multi-Precision Add-Carry Instruction Extensions)"},
        {7, 'b', 20, "SMAP (Supervisor Mode Access Prevention)"},
        {7, 'b', 21, "AVX512_IFMA (AVX-512 Integer Fused Multiply-Add Instructions)"},
        {7, 'b', 22, "PCOMMIT (PCOMMIT Instruction Deprecated)"},
        {7, 'b', 23, "CLFLUSHOPT (CLFLUSHOPT Instruction)"},
        {7, 'b', 24, "CLWB (Cache Line Write Back)"},
        {7, 'b', 25, "INTEL_PT (Intel Processor Trace)"},
        {7, 'b', 26, "AVX512PF (AVX-512 Prefetch Instructions)"},
        {7, 'b', 27, "AVX512ER (AVX-512 Exponential and Reciprocal Instructions)"},
        {7, 'b', 28, "AVX512CD (AVX-512 Conflict Detection Instructions)"},
        {7, 'b', 29, "SHA (Secure Hash Algorithm Extensions)"},
        {7, 'b', 30, "AVX512BW (AVX-512 Byte and Word Instructions)"},
        {7, 'b', 31, "AVX512VL (AVX-512 Vector Length Extensions)"}
    };


    CPUFeaturesChecker checker;
    checker.checkCPUFeatures(features);
    checker.printSupportedFeatures();
    checker.printUnsupportedFeatures();

    return 0;
}
