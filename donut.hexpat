#pragma magic [E8] @ 0x00

//imports
#include <std/mem.pat>

#define x86_Loader_Size 11603
#define DONUT_MAX_NAME 256
#ifndef MAX_PATH
    #define MAX_PATH 260
#endif

enum Entropy : s32 {
    DONUT_ENTROPY_DEFUALT = 3,
    DONUT_ENTROPY_RANDOM = 2,
    DONUT_ENTROPY_NONE = 1
};
enum Bypass : s32 {
    DONUT_BYPASS_NONE = 1,
    DONUT_BYPASS_ABORT = 2,
    DONUT_BYPASS_CONTINUE = 3
};
enum InstanceType : s32 {
    DONUT_INSTANCE_EMBED = 1,
    DONUT_INSTANCE_HTTP = 2,
    DONUT_INSTANCE_DNS = 3
};
enum ExitOptions : s32 {
    DONUT_OPT_EXIT_THREAD = 1,
    DONUT_OPT_EXIT_PROCESS = 2,
    DONUT_OPT_EXIT_BLOCK = 3
};
enum CompressionType : s32 {
    DONUT_COMPRESS_NONE = 1,
    DONUT_COMPRESS_APLIB = 2,
    DONUT_COMPRESS_LZNT1 = 3,
    DONUT_COMPRESS_XPRESS = 4
};
enum ModuleType : s32 {
    DONUT_MODULE_NET_DLL = 1,
    DONUT_MODULE_NET_EXE = 2,
    DONUT_MODULE_DLL = 3,
    DONUT_MODULE_EXE = 4,
    DONUT_MODULE_VBS = 5,
    DONUT_MODULE_JS = 6
};
enum Architecture : s32 {
    DONUT_ARCH_ANY = -1, //for vbs, js, xsl files
    DONUT_ARCH_X86 = 1,
    DONUT_ARCH_X64 = 2,
    DONUT_ARCH_X84 = 3
};
union hashTable {
    u64 hash;
    u64 addr;
};

struct DONUT_CRYPT {
    char EncKey[16];
    char EncNonce[16];
    u32 Unknown;
};
struct LoaderMulti {
    u8 x64StackAlignment[6];
    u32 LoaderSize;
    u8 X64_RSP_Align[22];
    u8 Loader[LoaderSize-22];
    u8 x86StackAlignment[3];
    u8 x86Loader[while(!std::mem::eof())];
};
struct DOTNetGUIDs {
    char xIID_IUnkown[16];
    char xIID_IDispatch[16];
    
    // GUIDs required to load .NET assemblies
    char xCLSID_CLRMetaHost[16];
    char xIID_ICLRMetaHost[16];
    char xIID_ICLRRuntimeHost[16];
    char xCLSID_CorRuntimeHost[16];
    char xIID_AppDomain [16];
    
    //GUIDs for VBS and JS files
    char xCLSID_ScriptLanguage[16];
    char xIID_IHost[16];
    char xIID_IActiveScript[16];
    char xIID_IActiveScriptSite[16];
    char xIID_IActiveScriptSiteWindow[16];
    char xIID_IActiveScriptParse32[16];
    char xIID_IActiveScriptParse64[16];
    u8 random[19];
};

struct instanceHeader {
    u32 InstanceSize;  
    DONUT_CRYPT instanceKey;
    u64 hashIv;
    hashTable ImportsMaybe[64];
    ExitOptions exitOption;
    Entropy entropy;
    u32 OriginalEntryPoint;
};
struct instanceBody {
    u32 apiCount;
    char dllNames[DONUT_MAX_NAME];
    char dataName[8];
    char kernelBase[12];
    char amsi[8];
    char clr[4];
    char wldp[8];
    char ntdll[8];
    char CommandLine[DONUT_MAX_NAME];
    char ExitAPI[DONUT_MAX_NAME];
    Bypass bypass;
    u32 headers;
    char wldpQuery[32];
    char wldpIsApproved[32];
    char amsiInit[16];
    char amsiScanBuf[16];
    char amsiScanStr[16];
    char etwEventWrite[16];
    char etwEventUnregister[20];
    char etwRet64[1];
    char etwRet32[4];
    char wscript[8];
    char wscript_exe[12];
    char decoy[MAX_PATH * 2];
    DOTNetGUIDs dotNetGUID;
    InstanceType InstanceType;
    char Server[DONUT_MAX_NAME];
    char username[DONUT_MAX_NAME];
    char password[DONUT_MAX_NAME];
    char httpReq[8];

    u8 sig[DONUT_MAX_NAME];
    u64 mac;
};
struct module {
    DONUT_CRYPT modKey;
    u64 modLen;
    ModuleType modType;
    u32 Unknown;
    CompressionType compressionType;
    u8 data[1300];
    s32 ModLen;
    s32 compressedModLen;
    u8 payload[compressedModLen];
};
struct instance {
    instanceHeader iHeader;
    if (iHeader.entropy == 1) {
        instanceBody iBody;
        module Module;
    }
    else {
        u8 encryptedData[iHeader.InstanceSize-572];
    }
};
struct donutLoader {
    u8 CallOp;
    u32 loaderAddr;
    instance Instance;
};

donutLoader Injector @ 0x0;
LoaderMulti loader @ Injector.loaderAddr+5;

if (Injector.Instance.iHeader.entropy != 1){
    std::mem::Section decryptedInstance = std::mem::create_section("Decrypted Instance");
    std::mem::set_section_size(decryptedInstance,Injector.Instance.iHeader.InstanceSize-572);
    std::mem::copy_value_to_section(Injector.Instance.encryptedData, decryptedInstance, 0x0);
    instanceBody sect @ 0x00 in decryptedInstance;
}