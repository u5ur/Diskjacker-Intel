#include "diskjacker.hpp"
#include <cstring>
#include <iostream>

int main()
{
    using namespace memory;

    if (!isHijacked())
    {
        std::cout << "Presence check failed (hook inactive or keys mismatch).\n";
        return 1;
    }
    std::cout << "Presence OK - keyed hypercall (PRIMARY_KEY / SECONDARY_KEY in RCX).\n";

    if (!init())
    {
        std::cout << "InitMemory failed on at least one logical processor.\n";
        return 1;
    }
    std::cout << "Payload guest mapping initialized per CPU.\n";

    const UINT64 guestCr3 = getCR3();
    std::cout << "Guest CR3 (this process): 0x" << std::hex << guestCr3 << std::dec << std::endl;

    const UINT64 systemCr3 = getSystemCr3();
    if (systemCr3)
        std::cout << "System CR3 (ring-0 guest sample): 0x" << std::hex << systemCr3 << std::dec << std::endl;

    UINT8 buffer[8] = {};
    const UINT64 bytesPhys = readPhysical(0x100107000, reinterpret_cast<UINT64>(buffer), sizeof(buffer));
    std::cout << "Read physical bytes transferred: " << bytesPhys << std::endl;

    std::cout << "Physical sample: ";
    for (size_t i = 0; i < sizeof(buffer); ++i)
        std::cout << std::hex << std::uppercase << static_cast<int>(buffer[i]) << " ";
    std::cout << std::dec << std::endl;

    const DWORD pid = getPIDByName(L"notepad.exe");
    std::cout << "PID (notepad.exe): " << pid << std::endl;
    if (!pid)
    {
        std::cout << "Start notepad.exe and re-run to exercise tracking.\n";
        system("pause");
        return 0;
    }

    setTrackedProcessName(L"notepad.exe");

    constexpr DWORD kMaxWaitMs = 120000;
    constexpr DWORD kPollMs = 10;
    DWORD waited = 0;
    UINT64 trackedPdb = 0;
    std::cout << "Waiting for tracked CR3 (keep Notepad in foreground / interact; up to "
              << (kMaxWaitMs / 1000) << " s)...\n";

    while (waited < kMaxWaitMs)
    {
        trackedPdb = getTrackedPDB();
        if (trackedPdb != 0)
            break;
        Sleep(kPollMs);
        waited += kPollMs;
    }

    std::cout << "Tracked process directory base: 0x" << std::hex << trackedPdb << std::dec << std::endl;

    if (!trackedPdb)
    {
        std::cout << "Timed out: payload never saw Notepad's CR3 on a VM-exit. "
                     "Rebuild payload after guest paging fix, ensure Notepad is running (x64), and retry.\n";
        system("pause");
        return 1;
    }

    const UINT64 trackedGs = getTrackedGs();
    if (trackedGs)
        std::cout << "Tracked GS base: 0x" << std::hex << trackedGs << std::dec << std::endl;

    GET_MODULE_INFO moduleInfo = getModuleInfo(L"Notepad.exe");
    std::cout << "Module base: 0x" << std::hex << moduleInfo.ModuleBaseAddress << std::dec << std::endl;
    std::cout << "Module size: " << std::dec << moduleInfo.ModuleSize << std::endl;

    memset(buffer, 0, sizeof(buffer));
    const UINT64 bytesVirt =
        readVirtual(moduleInfo.ModuleBaseAddress, reinterpret_cast<UINT64>(buffer), sizeof(buffer), trackedPdb);
    std::cout << "Read virtual bytes transferred: " << bytesVirt << std::endl;

    std::cout << "Virtual sample: ";
    for (size_t i = 0; i < sizeof(buffer); ++i)
        std::cout << std::hex << std::uppercase << static_cast<int>(buffer[i]) << " ";
    std::cout << std::dec << std::endl;

    system("pause");
    return 0;
}
