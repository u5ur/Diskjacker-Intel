// https://github.com/noahware/hyper-reV/tree/main/hyperv-attachment
#include <xmmintrin.h>
#include <ntdef.h>
#include <intrin.h>
#include "shared.hpp"
#include "memory.hpp"
#include <cstdint>
#include "ia32.hpp"

extern "C" __declspec(dllexport) INT64 OriginalOffsetFromHook = 0x0;
extern "C" void JmpToOriginal(void* Arg1, void* Arg2, uint64_t ToJmp);

struct TrapFrame
{
    uint64_t Rax, Rcx, Rdx, Rbx;
    uint64_t Rsp, Rbp, Rsi, Rdi;
    uint64_t R8, R9, R10, R11;
    uint64_t R12, R13, R14, R15;
};

static uint64_t sInitialized = 0;
static uint64_t sSystemCr3 = 0;

static uint64_t VmRead(uint64_t Field)
{
    uint64_t Value = 0;
    __vmx_vmread(Field, &Value);
    return Value;
}

static void VmWrite(uint64_t Field, uint64_t Value)
{
    __vmx_vmwrite(Field, Value);
}

static void AdvanceGuestRip()
{
    VmWrite(VMCS_GUEST_RIP, VmRead(VMCS_GUEST_RIP) + VmRead(VMCS_VMEXIT_INSTRUCTION_LENGTH));
}

static uint64_t GuestCr3Raw()
{
    return VmRead(VMCS_GUEST_CR3);
}

static uint64_t GuestCr3Physical()
{
    return Cr3ToPml4Physical(GuestCr3Raw());
}

static void InitMemory()
{
    if (sInitialized)
        return;

    if (MemoryInit())
        sInitialized = 1;
}

static void TryFindProcessCr3()
{
    if (!currentPIDTracked || currentTrackedPdb)
        return;

    uint64_t Cs = 0;
    __vmx_vmread(VMCS_GUEST_CS_SELECTOR, &Cs);

    if ((Cs & 0x3) != 3)
        return;

    uint64_t GsBase = 0;
    __vmx_vmread(VMCS_GUEST_GS_BASE, &GsBase);

    if (!GsBase)
        return;

    const uint64_t GuestCr3Phys = GuestCr3Physical();

    if (!MemoryTranslateGuestVirtual(GuestCr3Phys, GsBase + 0x40, MapSource))
        return;

    uint64_t Pid = 0;

    if (!MemoryCopyGuestVirtual(
            GuestCr3Phys,
            GsBase + 0x40,
            __readcr3(),
            reinterpret_cast<uint64_t>(&Pid),
            sizeof(Pid)))
        return;

    if (Pid != currentPIDTracked)
        return;

    currentTrackedPdb = GuestCr3Phys;
    currentTrackedGS = GsBase;
}

static void TryFindSystemCr3()
{
    if (sSystemCr3)
        return;

    uint64_t Cs = 0;
    __vmx_vmread(VMCS_GUEST_CS_SELECTOR, &Cs);

    if ((Cs & 0x3) != 0)
        return;

    sSystemCr3 = GuestCr3Physical();
}

static uint64_t HandlePhysicalMemoryOp(const TrapFrame* Tf, MemoryOp Op)
{
    const uint64_t GuestCr3Phys = GuestCr3Physical();
    const uint64_t GuestPhys = Tf->Rdx;
    const uint64_t GuestVirt = Tf->R8;
    uint64_t SizeRemaining = Tf->R9;
    uint64_t BytesDone = 0;

    while (SizeRemaining != 0)
    {
        const uint64_t BufMapped = MemoryMapGuestVirtual(GuestCr3Phys, GuestVirt + BytesDone, MapDestination);
        const uint64_t PhysMapped = MemoryMapPage(GuestPhys + BytesDone, MapSource);

        if (!BufMapped || !PhysMapped)
            break;

        const uint64_t BufLeft = PAGE_SIZE - ((GuestVirt + BytesDone) & PAGE_MASK);
        const uint64_t PhysLeft = PAGE_SIZE - ((GuestPhys + BytesDone) & PAGE_MASK);
        const uint64_t CopySize = SizeRemaining < BufLeft
            ? (SizeRemaining < PhysLeft ? SizeRemaining : PhysLeft)
            : (BufLeft < PhysLeft ? BufLeft : PhysLeft);

        if (!CopySize)
            break;

        if (Op == MemoryOp::Write)
            CopyMemory(reinterpret_cast<void*>(PhysMapped), reinterpret_cast<const void*>(BufMapped), CopySize);
        else
            CopyMemory(reinterpret_cast<void*>(BufMapped), reinterpret_cast<const void*>(PhysMapped), CopySize);

        SizeRemaining -= CopySize;
        BytesDone += CopySize;
    }

    return BytesDone;
}

static uint64_t HandleVirtualMemoryOp(const TrapFrame* Tf, MemoryOp Op, uint64_t PageDirectoryBasePfn)
{
    const uint64_t PageDirectoryBase = PageDirectoryBasePfn << 12;

    const uint64_t SrcCr3Phys = (Op == MemoryOp::Read)
        ? PageDirectoryBase
        : GuestCr3Physical();

    const uint64_t DstCr3Phys = (Op == MemoryOp::Read)
        ? GuestCr3Physical()
        : PageDirectoryBase;

    const uint64_t SrcGva = (Op == MemoryOp::Read) ? Tf->R8 : Tf->Rdx;
    const uint64_t DstGva = (Op == MemoryOp::Read) ? Tf->Rdx : Tf->R8;
    uint64_t SizeRemaining = Tf->R9;
    uint64_t BytesDone = 0;

    while (SizeRemaining != 0)
    {
        const uint64_t SrcMapped = MemoryMapGuestVirtual(SrcCr3Phys, SrcGva + BytesDone, MapSource);
        const uint64_t DstMapped = MemoryMapGuestVirtual(DstCr3Phys, DstGva + BytesDone, MapDestination);

        if (!SrcMapped || !DstMapped)
            break;

        const uint64_t SrcLeft = PAGE_SIZE - ((SrcGva + BytesDone) & PAGE_MASK);
        const uint64_t DstLeft = PAGE_SIZE - ((DstGva + BytesDone) & PAGE_MASK);
        const uint64_t CopySize = SizeRemaining < SrcLeft
            ? (SizeRemaining < DstLeft ? SizeRemaining : DstLeft)
            : (SrcLeft < DstLeft ? SrcLeft : DstLeft);

        if (!CopySize)
            break;

        CopyMemory(reinterpret_cast<void*>(DstMapped), reinterpret_cast<const void*>(SrcMapped), CopySize);

        SizeRemaining -= CopySize;
        BytesDone += CopySize;
    }

    return BytesDone;
}

static uint64_t HandleTranslateGuestVirtual(const TrapFrame* Tf)
{
    const uint64_t TargetCr3Raw = Tf->R8;
    const uint64_t DirPhys = Cr3ToPml4Physical(TargetCr3Raw);
    return MemoryTranslateGuestVirtual(DirPhys, Tf->Rdx, MapSource);
}

static uint64_t HandleSetTrackedPid(const TrapFrame* Tf)
{
    currentPIDTracked = Tf->Rdx;
    currentTrackedPdb = 0;
    currentTrackedGS = 0;
    return 1;
}

static bool HandleCommand(TrapFrame* Tf)
{
    const CommandInfo Info = {.Value = Tf->Rcx};

    if (Info.PrimaryKey != PRIMARY_KEY)
        return false;

    if (Info.SecondaryKey != SECONDARY_KEY)
        return false;

    const uint64_t guestCr3Raw = GuestCr3Raw();
    const uint64_t guestCr3Phys = GuestCr3Physical();

    switch (Info.Type)
    {
    case CommandType::ReadGuestCr3:
        Tf->Rax = guestCr3Raw;
        break;

    case CommandType::SetTrackedPid:
        Tf->Rax = HandleSetTrackedPid(Tf);
        break;

    case CommandType::GetTrackedCr3:
        Tf->Rax = currentTrackedPdb;
        break;

    case CommandType::GetTrackedGs:
        Tf->Rax = currentTrackedGS;
        break;

    case CommandType::GetSystemCr3:
        Tf->Rax = sSystemCr3;
        break;

    case CommandType::GuestPhysicalMemoryOp:
    {
        const PhysOpCommandInfo PhysInfo = {.Value = Tf->Rcx};
        Tf->Rax = HandlePhysicalMemoryOp(Tf, PhysInfo.Operation);
        break;
    }

    case CommandType::GuestVirtualMemoryOp:
    {
        const VirtOpCommandInfo VirtInfo = {.Value = Tf->Rcx};
        Tf->Rax = HandleVirtualMemoryOp(Tf, VirtInfo.Operation, VirtInfo.PageDirectoryBase);
        break;
    }

    case CommandType::TranslateGuestVirtual:
        Tf->Rax = HandleTranslateGuestVirtual(Tf);
        break;

    case CommandType::InitMemory:
        Tf->Rax = MemoryInit() ? 1 : 0;
        break;

    case CommandType::CheckPresence:
        Tf->Rax = CPUID_RETURN_VALUE;
        break;

    case CommandType::GetModuleInfo:
    {
        const uint64_t gva = Tf->R8;
        GET_MODULE_INFO gi = {};
        if (!MemoryCopyGuestVirtual(guestCr3Phys, gva, __readcr3(), reinterpret_cast<uint64_t>(&gi), sizeof(gi)))
            return false;
        Tf->Rax = MemoryGetModuleOfTracked(gi.ModuleName, &gi.ModuleBaseAddress, &gi.ModuleSize);
        if (!MemoryCopyGuestVirtual(__readcr3(), reinterpret_cast<uint64_t>(&gi), guestCr3Phys, gva, sizeof(gi)))
            return false;
        break;
    }

    default:
        return false;
    }

    AdvanceGuestRip();
    return true;
}

UINT64 VmExitHandler(void* Arg1, void* Arg2)
{
    TrapFrame* const Tf = Arg1 ? *reinterpret_cast<TrapFrame**>(Arg1) : nullptr;

    InitMemory();

    if (sInitialized != 0 && currentPIDTracked != 0 && currentTrackedPdb == 0)
        TryFindProcessCr3();

    if (sInitialized != 0 && sSystemCr3 == 0)
        TryFindSystemCr3();

    const uint64_t ExitReason = VmRead(VMCS_EXIT_REASON);
    const uint16_t BasicReason = static_cast<uint16_t>(VMX_VMEXIT_REASON_BASIC_EXIT_REASON(ExitReason));

    if (Tf && BasicReason == VMX_EXIT_REASON_EXECUTE_CPUID && sInitialized != 0 && HandleCommand(Tf))
        return 0;

    JmpToOriginal(Arg1, Arg2, OriginalOffsetFromHook);
    __assume(0);
}
