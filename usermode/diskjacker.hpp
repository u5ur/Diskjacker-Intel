#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include "shared.hpp"
#include <Windows.h>
#include <tlhelp32.h>
#include <cwchar>
#include <string>
#include <winternl.h>

namespace memory
{
extern "C" UINT64 SendCommand(UINT64 rcx, UINT64 rdx, UINT64 r8, UINT64 r9);

inline CommandInfo MakeCommandInfo(const CommandType Type)
{
    CommandInfo Info = {};
    Info.PrimaryKey = PRIMARY_KEY;
    Info.SecondaryKey = SECONDARY_KEY;
    Info.Type = Type;
    return Info;
}

inline bool isHijacked()
{
    return SendCommand(MakeCommandInfo(CommandType::CheckPresence).Value, 0, 0, 0) == CPUID_RETURN_VALUE;
}

inline DWORD getPIDByName(const std::wstring& processName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe))
    {
        CloseHandle(hSnapshot);
        return 0;
    }

    do
    {
        if (processName == pe.szExeFile)
        {
            CloseHandle(hSnapshot);
            return pe.th32ProcessID;
        }
    } while (Process32NextW(hSnapshot, &pe));

    CloseHandle(hSnapshot);
    return 0;
}

inline bool init()
{
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    for (DWORD_PTR core = 0; core < sysInfo.dwNumberOfProcessors; ++core)
    {
        const DWORD_PTR affinityMask = 1ULL << core;
        const HANDLE currentThread = GetCurrentThread();
        const DWORD_PTR previousAffinityMask = SetThreadAffinityMask(currentThread, affinityMask);

        if (!previousAffinityMask)
            continue;

        const UINT64 status = SendCommand(MakeCommandInfo(CommandType::InitMemory).Value, 0, 0, 0);
        if (status == 0)
        {
            SetThreadAffinityMask(currentThread, previousAffinityMask);
            return false;
        }

        SetThreadAffinityMask(currentThread, previousAffinityMask);
    }

    return true;
}

inline UINT64 getCR3()
{
    return SendCommand(MakeCommandInfo(CommandType::ReadGuestCr3).Value, 0, 0, 0);
}

inline UINT64 getSystemCr3()
{
    return SendCommand(MakeCommandInfo(CommandType::GetSystemCr3).Value, 0, 0, 0);
}

inline UINT64 getTrackedGs()
{
    return SendCommand(MakeCommandInfo(CommandType::GetTrackedGs).Value, 0, 0, 0);
}

inline UINT64 translateGuestVirtual(UINT64 guestVirtualAddress, UINT64 targetCr3)
{
    return SendCommand(
        MakeCommandInfo(CommandType::TranslateGuestVirtual).Value,
        guestVirtualAddress,
        targetCr3,
        0);
}

inline UINT64 readPhysical(UINT64 physicalAddress, UINT64 buffer, UINT64 size, UINT64 cr3 = 0)
{
    PhysOpCommandInfo Info = {};
    Info.PrimaryKey = PRIMARY_KEY;
    Info.SecondaryKey = SECONDARY_KEY;
    Info.Type = CommandType::GuestPhysicalMemoryOp;
    Info.Operation = MemoryOp::Read;

    UNREFERENCED_PARAMETER(cr3);
    return SendCommand(Info.Value, physicalAddress, buffer, size);
}

inline UINT64 readVirtual(UINT64 virtualAddress, UINT64 buffer, UINT64 size, UINT64 targetCr3 = 0)
{
    VirtOpCommandInfo Info = {};
    Info.PrimaryKey = PRIMARY_KEY;
    Info.SecondaryKey = SECONDARY_KEY;
    Info.Type = CommandType::GuestVirtualMemoryOp;
    Info.Operation = MemoryOp::Read;
    Info.PageDirectoryBase = (targetCr3 ? targetCr3 : getCR3()) >> 12;

    return SendCommand(Info.Value, buffer, virtualAddress, size);
}

inline UINT64 writeVirtual(UINT64 virtualAddress, UINT64 buffer, UINT64 size, UINT64 targetCr3 = 0)
{
    VirtOpCommandInfo Info = {};
    Info.PrimaryKey = PRIMARY_KEY;
    Info.SecondaryKey = SECONDARY_KEY;
    Info.Type = CommandType::GuestVirtualMemoryOp;
    Info.Operation = MemoryOp::Write;
    Info.PageDirectoryBase = (targetCr3 ? targetCr3 : getCR3()) >> 12;

    return SendCommand(Info.Value, buffer, virtualAddress, size);
}

inline UINT64 getTrackedPDB()
{
    return SendCommand(MakeCommandInfo(CommandType::GetTrackedCr3).Value, 0, 0, 0);
}

inline GET_MODULE_INFO getModuleInfo(const std::wstring& moduleName)
{
    GET_MODULE_INFO data = {};
    wcsncpy(data.ModuleName, moduleName.c_str(), (sizeof(data.ModuleName) / sizeof(wchar_t)) - 1);

    const UINT64 trackedCr3 = getTrackedPDB();
    const UINT64 gs = getTrackedGs();
    if (!trackedCr3 || !gs)
        return data;

    UINT64 peb = 0;
    if (readVirtual(gs + 0x60, reinterpret_cast<UINT64>(&peb), sizeof(peb), trackedCr3) != sizeof(peb) || !peb)
        return data;

    UINT64 ldr = 0;
    if (readVirtual(peb + 0x18, reinterpret_cast<UINT64>(&ldr), sizeof(ldr), trackedCr3) != sizeof(ldr) || !ldr)
        return data;

    const UINT64 listHead = ldr + 0x10;
    UINT64 curr = 0;
    if (readVirtual(listHead, reinterpret_cast<UINT64>(&curr), sizeof(curr), trackedCr3) != sizeof(curr) || !curr)
        return data;

    for (int n = 0; n < 512 && curr != listHead; ++n)
    {
        UINT64 dllBase = 0;
        ULONG sizeOfImage = 0;
        UNICODE_STRING baseName = {};

        if (readVirtual(curr + 0x30, reinterpret_cast<UINT64>(&dllBase), sizeof(dllBase), trackedCr3) != sizeof(dllBase))
            break;
        if (readVirtual(curr + 0x40, reinterpret_cast<UINT64>(&sizeOfImage), sizeof(sizeOfImage), trackedCr3) !=
            sizeof(sizeOfImage))
            break;
        if (readVirtual(curr + 0x58, reinterpret_cast<UINT64>(&baseName), sizeof(baseName), trackedCr3) !=
            sizeof(baseName))
            break;

        wchar_t nameBuf[260] = {};
        if (baseName.Buffer != nullptr && baseName.Length > 0)
        {
            const UINT64 bufAddr = reinterpret_cast<UINT64>(baseName.Buffer);
            const SIZE_T byteLen = baseName.Length;
            if (byteLen < sizeof(nameBuf))
            {
                if (readVirtual(bufAddr, reinterpret_cast<UINT64>(nameBuf), byteLen, trackedCr3) != byteLen)
                {
                    UINT64 next = 0;
                    if (readVirtual(curr, reinterpret_cast<UINT64>(&next), sizeof(next), trackedCr3) != sizeof(next))
                        break;
                    curr = next;
                    continue;
                }
                nameBuf[byteLen / sizeof(wchar_t)] = L'\0';
            }
        }

        if (nameBuf[0] != L'\0' && _wcsicmp(nameBuf, moduleName.c_str()) == 0)
        {
            data.ModuleBaseAddress = dllBase;
            data.ModuleSize = sizeOfImage;
            break;
        }

        UINT64 next = 0;
        if (readVirtual(curr, reinterpret_cast<UINT64>(&next), sizeof(next), trackedCr3) != sizeof(next))
            break;
        curr = next;
    }

    return data;
}

template <typename T>
const T Read(const std::uintptr_t address) noexcept
{
    T value = {};
    readVirtual(address, reinterpret_cast<UINT64>(&value), sizeof(T));
    return value;
}

template <typename T>
void Write(const std::uintptr_t address, const T& value) noexcept
{
    writeVirtual(address, reinterpret_cast<UINT64>(&value), sizeof(T));
}

inline UINT64 setTrackedProcessPID(UINT32 pid)
{
    return SendCommand(MakeCommandInfo(CommandType::SetTrackedPid).Value, pid, 0, 0);
}

inline UINT64 setTrackedProcessName(const std::wstring& processName)
{
    return setTrackedProcessPID(getPIDByName(processName));
}

}
