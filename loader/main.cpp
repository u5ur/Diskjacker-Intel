#include "kdmapper/kdmapper.hpp"
#include "kdmapper/intel_driver.hpp"
#include <iostream>
#include <virtdisk.h>
#pragma comment(lib, "virtdisk.lib")

HANDLE iqvw64e_device_handle;
HANDLE vhdHandle;

bool DestroyVHD()
{
    if (vhdHandle == INVALID_HANDLE_VALUE) {
        kdmLog("VHD handle is invalid.\n");
        return false;
	}
    HRESULT result = DetachVirtualDisk(vhdHandle, DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
    if (result != ERROR_SUCCESS) {
        kdmLog("Failed to detach VHD: %lu\n", result);
        return false;
    }
    else {
        kdmLog("VHD detached.\n");
    }

    CloseHandle(vhdHandle);

    if (DeleteFileW(L"C:\\vhd.vhd")) {
        kdmLog("VHD file deleted.\n");
    }
    else {
        kdmLog("Failed to delete VHD file.\n");
        return false;
    }
    return true;
}
bool CreateVHD()
{
    if (GetFileAttributesW(L"C:\\vhd.vhd") != INVALID_FILE_ATTRIBUTES) {
        if (!DeleteFileW(L"C:\\vhd.vhd")) {
            kdmLog("Failed to delete existing VHD file.\n");
            return false;
        } else {
            kdmLog("Existing VHD file deleted.\n");
        }
    }

    VIRTUAL_STORAGE_TYPE storageType = {
       VIRTUAL_STORAGE_TYPE_DEVICE_VHD,
       GUID_NULL
    };

    CREATE_VIRTUAL_DISK_PARAMETERS params{ };
    params.Version = CREATE_VIRTUAL_DISK_VERSION_1;
    params.Version1.MaximumSize = 3ull * 1024 * 1024; // 1MB
    params.Version1.BlockSizeInBytes = CREATE_VIRTUAL_DISK_PARAMETERS_DEFAULT_BLOCK_SIZE;
    params.Version1.SectorSizeInBytes = CREATE_VIRTUAL_DISK_PARAMETERS_DEFAULT_SECTOR_SIZE;
    params.Version1.ParentPath = NULL;

    HRESULT hr = CreateVirtualDisk(
        &storageType,
        L"C:\\vhd.vhd",
        VIRTUAL_DISK_ACCESS_ALL,
        NULL,
        CREATE_VIRTUAL_DISK_FLAG_NONE,
        0,
        &params,
        NULL,
        &vhdHandle
    );

    if (hr != 0) return false;
    ATTACH_VIRTUAL_DISK_PARAMETERS attachParams{ };
    attachParams.Version = ATTACH_VIRTUAL_DISK_VERSION_1;

    hr = AttachVirtualDisk(
        vhdHandle,
        NULL,
        ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME,
        0,
        &attachParams,
        NULL
    );

    if (hr != 0) return false;

    return true;
}

LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
    if (ExceptionInfo && ExceptionInfo->ExceptionRecord)
        kdmLog(L"[!!] Crash at addr 0x" << ExceptionInfo->ExceptionRecord->ExceptionAddress << L" by 0x" << std::hex << ExceptionInfo->ExceptionRecord->ExceptionCode << std::endl);
    else
        kdmLog(L"[!!] Crash" << std::endl);

    if (iqvw64e_device_handle)
        intel_driver::Unload();
    if (vhdHandle)
        DestroyVHD();


    return EXCEPTION_EXECUTE_HANDLER;
}

int wmain(const int argc, wchar_t** argv)
{
    if (argc < 2) {
        kdmLog(L"Usage: " << argv[0] << L" <driver_image_path>" << std::endl);
        return -1;
	}
	SetUnhandledExceptionFilter(SimplestCrashHandler);
	intel_driver::Load();
	if (iqvw64e_device_handle == INVALID_HANDLE_VALUE) {
		return -1;
	}
    if (!CreateVHD()) {
        kdmLog(L"[-] Failed to create VHD" << std::endl);
        intel_driver::Unload();
        return -1;
	}
	std::vector<uint8_t> raw_image = { 0 };
	if (!kdmUtils::ReadFileToMemory(argv[1], &raw_image)) {
        kdmLog(L"[-] Failed to read image to memory" << std::endl);
		intel_driver::Unload();
		return -1;
	}
	NTSTATUS exitCode = 0;
	if (!kdmapper::MapDriver(raw_image.data(), 0, 0, true, true, kdmapper::AllocationMode::AllocateIndependentPages, false, 0, &exitCode)) {
        kdmLog(L"[-] Failed to map" << std::endl);
		intel_driver::Unload();
		return -1;
	}
	intel_driver::Unload();
	DestroyVHD();
    system("pause");
    return 0;
}