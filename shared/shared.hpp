#pragma once
#include <basetsd.h>

#define CPUID_RETURN_VALUE 0x123456789

constexpr UINT64 PRIMARY_KEY = 0x4E47;
constexpr UINT64 SECONDARY_KEY = 0x7F;

enum class CommandType : UINT64
{
    ReadGuestCr3 = 0,
    GuestPhysicalMemoryOp = 1,
    GuestVirtualMemoryOp = 2,
    TranslateGuestVirtual = 3,
    SetTrackedPid = 4,
    GetTrackedCr3 = 5,
    GetTrackedGs = 6,
    GetSystemCr3 = 7,
    InitMemory = 8,
    CheckPresence = 9,
    GetModuleInfo = 10,
};

enum class MemoryOp : UINT64
{
    Read = 0,
    Write = 1,
};

union CommandInfo
{
    UINT64 Value;
    struct
    {
        UINT64 PrimaryKey : 16;
        CommandType Type : 4;
        UINT64 SecondaryKey : 7;
        UINT64 Reserved : 37;
    };
};

union PhysOpCommandInfo
{
    UINT64 Value;
    struct
    {
        UINT64 PrimaryKey : 16;
        CommandType Type : 4;
        UINT64 SecondaryKey : 7;
        MemoryOp Operation : 1;
        UINT64 Unused : 36;
    };
};

union VirtOpCommandInfo
{
    UINT64 Value;
    struct
    {
        UINT64 PrimaryKey : 16;
        CommandType Type : 4;
        UINT64 SecondaryKey : 7;
        MemoryOp Operation : 1;
        UINT64 PageDirectoryBase : 36;
    };
};

typedef struct _GET_MODULE_INFO
{
    wchar_t ModuleName[64];
    UINT64 ModuleBaseAddress;
    UINT64 ModuleSize;
} GET_MODULE_INFO;
