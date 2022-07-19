
// @x9090 - April 25 2022
#include "reghooks.h"
#include "backend.h"
#include "globals.h"
#include "reghandle_table.h"
#include "nt.h"
#include "utils.h"
#include <regex>

std::vector<std::uint64_t> PfnRegOpenKeyExA;
std::vector<std::uint64_t> PfnRegOpenKeyExW;
std::vector<std::uint64_t> PfnRegCreateKeyExA;
std::vector<std::uint64_t> PfnRegCreateKeyExW;
std::vector<std::uint64_t> PfnRegQueryValueExA;
std::vector<std::uint64_t> PfnRegQueryValueExW;
std::vector<std::uint64_t> PfnRegGetValueW;
std::vector<std::uint64_t> PfnRegCloseKey;

//
// NT registries declaration
//

NTQUERYVALUEKEY NtQueryValueKey;
NTQUERYKEY NtQueryKey;
NTOPENKEY NtOpenKey;
NTCLOSE NtClose;


bool EnumerateRegistrySymbols() {

    PfnRegOpenKeyExW = g_Dbg.GetSymbols("KERNELBASE!RegOpenKeyExW*");

    if (PfnRegOpenKeyExW.size() == 0 || PfnRegOpenKeyExW.size() != 2) {
        fmt::print("Failed resolve registry symbols: KERNELBASE!RegOpenKeyExW*");
        std::abort();
    }

    PfnRegOpenKeyExA = g_Dbg.GetSymbols("KERNELBASE!RegOpenKeyExA*");

    if (PfnRegOpenKeyExA.size() == 0 || PfnRegOpenKeyExA.size() != 2) {
        fmt::print("Failed resolve registry symbols: KERNELBASE!RegOpenKeyExA*");
        std::abort();
    }

    PfnRegCreateKeyExA = g_Dbg.GetSymbols("KERNELBASE!RegCreateKeyExA*");

    if (PfnRegCreateKeyExA.size() == 0 || PfnRegCreateKeyExA.size() != 2) {
        fmt::print("Failed resolve registry symbols: KERNELBASE!RegCreateKeyExA*");
        std::abort();
    }

    PfnRegCreateKeyExW = g_Dbg.GetSymbols("KERNELBASE!RegCreateKeyExW*");

    if (PfnRegCreateKeyExW.size() == 0 || PfnRegCreateKeyExW.size() != 2) {
        fmt::print("Failed resolve registry symbols: KERNELBASE!RegCreateKeyExW*");
        std::abort();
    }

    PfnRegQueryValueExA = g_Dbg.GetSymbols("KERNELBASE!RegQueryValueExA*");

    if (PfnRegQueryValueExA.size() == 0 || PfnRegQueryValueExA.size() != 2) {
        fmt::print("Failed resolve registry symbols: KERNELBASE!RegQueryValueExA*");
        std::abort();
    }

    PfnRegQueryValueExW = g_Dbg.GetSymbols("KERNELBASE!RegQueryValueExW*");

    if (PfnRegQueryValueExW.size() == 0 || PfnRegQueryValueExW.size() != 2) {
        fmt::print("Failed resolve registry symbols: KERNELBASE!RegQueryValueExW*");
        std::abort();
    }

    PfnRegGetValueW = g_Dbg.GetSymbols("KERNELBASE!RegGetValueW*");

    if (PfnRegGetValueW.size() == 0 || PfnRegGetValueW.size() != 2) {
        fmt::print("Failed resolve registry symbols: KERNELBASE!RegGetValueW*");
        std::abort();
    }

    PfnRegCloseKey = g_Dbg.GetSymbols("KERNELBASE!RegCloseKey*");

    if (PfnRegCloseKey.size() == 0 || PfnRegCloseKey.size() != 2) {
        fmt::print("Failed resolve registry symbols: KERNELBASE!RegCloseKey*");
        std::abort();
    }

    return true;
}

bool ResolveNtReg() {
	NtQueryValueKey = (NTQUERYVALUEKEY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryValueKey");
	if (!NtQueryValueKey) {
		fmt::print("Failed to resolve ntdll!NtQueryValueKey\n");
		std::abort();
	}

    NtQueryKey = (NTQUERYKEY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryKey");
    if (!NtQueryKey) {
        fmt::print("Failed to resolve ntdll!NtQueryKey\n");
        std::abort();
    }

	NtOpenKey = (NTOPENKEY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenKey");
	if (!NtOpenKey) {
		fmt::print("Failed to resolve ntdll!NtOpenKey\n");
		std::abort();
	}

	NtClose = (NTCLOSE)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtClose");
	if (!NtClose) {
		fmt::print("Failed to resolve ntdll!NtClose\n");
		std::abort();
	}

    return true;
}

bool SetupRegistryHooks() {

    //
    //  Registry APIs has ambiguous symbols
    // 
    //    ||0:0:006> x kernelbase!regOpenkeyExW*
    //  00007ff9`e5dad1a0 KERNELBASE!RegOpenKeyExW (void)
    //  00007ff9`e5d578a0 KERNELBASE!RegOpenKeyExW (RegOpenKeyExW)
    //
    //  ||0:0:006> u KERNELBASE!RegQueryValueExW
    //  Matched: 00007ff9`e5d578d0 KERNELBASE!RegQueryValueExW(void)
    //  Matched: 00007ff9`e5e68580 KERNELBASE!RegQueryValueExW(void)
    //  Ambiguous symbol error at 'KERNELBASE!RegQueryValueExW'
    //
    EnumerateRegistrySymbols();
    ResolveNtReg();
    for (const auto offset : PfnRegOpenKeyExW) {
        if (!g_Backend->SetBreakpoint(Gva_t(offset), [](Backend_t* Backend) {
            /*LSTATUS RegOpenKeyExW(
                [in]           HKEY    hKey,
                [in, optional] LPCWSTR lpSubKey,
                [in]           DWORD   ulOptions,
                [in]           REGSAM  samDesired,
                [out]          PHKEY   phkResult
            );*/
            LSTATUS Status = ERROR_SUCCESS;
            const HANDLE Handle = HANDLE(Backend->GetArg(0));
            Gva_t vaSubKey = Backend->GetArgGva(1);
            Gva_t phkResult = Backend->GetArgGva(4);
            std::u16string SubKey;

            if (vaSubKey != Gva_t(0))
                SubKey = Backend->VirtReadWideString(vaSubKey, 256);
            
            RegDebugPrint("KERNELBASE!RegOpenKeyExW(hKey={}, Subkey={})\n", fmt::ptr(Handle), u16stringToString(SubKey));

            //
            // If the handle is not seen previously,
            // for example, combase.dll will obtain HKCU\Software\Classes hkey
            // via combase!OpenClassesRootKeyExW and this hkey will be used subsequently
            // by other routines such as combase!CComRegCatalog::GetClassInfoW 
            // Therefore, we need some heuristic ways to determine the root key
            //

            if (!g_RegHandleTable.KnownRootKey(Handle) && !g_RegHandleTable.Has(Handle)) {
                const Gva_t Rsp = Gva_t(g_Backend->Rsp());
                const uint64_t ReturnAddress = g_Backend->VirtRead8(Rsp);
                std::string FnName = g_Dbg.GetName(ReturnAddress, true);
                if (FnName.find("combase!CComRegCatalog::GetClassInfoW") == 0 && toLowerWString(SubKey).find(u"clsid") == 0) {
                    g_GuestRegistry.AddHandle(Handle, u"HKLM\\Software\\Classes");
                }
				else if (FnName.find("combase!OpenClassesRootKeyExW") == 0 && toLowerWString(SubKey).find(u"clsid") == 0) {
                    // The handle here is stored in combase!cachedHKCR
					g_GuestRegistry.AddHandle(Handle, u"HKCR\\");
				}
                else {
                    __debugbreak();
                    RegDebugPrint("Unknown heuristic handle registry called from: {}\n", FnName);
                }
            }


            //
            // Ensure that the key does exists in native host (guest too)
            // before returning guest handle
            //
            
            HKEY hSubKey;
            if ((Status = g_GuestRegistry._RegOpenKeyEx((HKEY)Handle, SubKey, &hSubKey)) == ERROR_SUCCESS){
                HANDLE GuestHandle = g_RegHandleTable.AllocateGuestHandle();
                Backend->VirtWriteStructDirty(phkResult, &GuestHandle);
                RegDebugPrint("\"{}\" exists so opening a guest handle {} => {}:{}\n", u16stringToString(SubKey), fmt::ptr(Handle), fmt::ptr(GuestHandle), fmt::ptr(hSubKey));
                g_RegHandleTable.AddHandle(GuestHandle, hSubKey);
            } 

            Backend->SimulateReturnFromFunction(Status);
            })) {
            return false;
        }
    }

    for (const auto offset : PfnRegCreateKeyExW) {
        if (!g_Backend->SetBreakpoint(Gva_t(offset), [](Backend_t* Backend) {
            /*LSTATUS RegCreateKeyExW(
              [in]            HKEY                        hKey,
              [in]            LPCWSTR                     lpSubKey,
                              DWORD                       Reserved,
              [in, optional]  LPWSTR                      lpClass,
              [in]            DWORD                       dwOptions,
              [in]            REGSAM                      samDesired,
              [in, optional]  const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
              [out]           PHKEY                       phkResult,
              [out, optional] LPDWORD                     lpdwDisposition
            );*/
            LSTATUS Status = ERROR_SUCCESS;
            const HANDLE Handle = HANDLE(Backend->GetArg(0));
            Gva_t vaSubKey = Backend->GetArgGva(1);
            Gva_t Class = Backend->GetArgGva(3);
            Gva_t Options = Backend->GetArgGva(4);
            const REGSAM SamDesired = Backend->GetArg(5);
            Gva_t vaSecurityAttributes = Backend->GetArgGva(6);
            Gva_t phkResult = Backend->GetArgGva(7);
            Gva_t Disposition = Backend->GetArgGva(8);
            std::u16string SubKey;

            if (vaSubKey != Gva_t(0))
                SubKey = Backend->VirtReadWideString(vaSubKey, 256);

            RegDebugPrint("KERNELBASE!RegCreateKeyExW(hKey={}, SubKey={})\n", fmt::ptr(Handle), u16stringToString(SubKey));

            // TODO: xxx
            std::abort();
            Backend->SimulateReturnFromFunction(Status);
            })) {
            return false;
        }

    }

    for (const auto offset : PfnRegQueryValueExW) {
        if (!g_Backend->SetBreakpoint(Gva_t(offset), [](Backend_t* Backend) {
            /*LSTATUS RegQueryValueExW(
              [in]                HKEY    hKey,
              [in, optional]      LPCWSTR lpValueName,
                                  LPDWORD lpReserved,
              [out, optional]     LPDWORD lpType,
              [out, optional]     LPBYTE  lpData,
              [in, out, optional] LPDWORD lpcbData
            );*/
            LSTATUS Status = ERROR_SUCCESS;
            const HANDLE Handle = HANDLE(Backend->GetArg(0));
            Gva_t vaValue = Backend->GetArgGva(1);
            Gva_t Type = Backend->GetArgGva(3);
            Gva_t Data = Backend->GetArgGva(4);
            Gva_t cbData = Backend->GetArgGva(6);
            std::u16string Value;

            if (vaValue != Gva_t(0))
                Value = Backend->VirtReadWideString(vaValue, 256);

            RegDebugPrint("KERNELBASE!RegQueryValueExW(hKey={}, Value={})\n", fmt::ptr(Handle), u16stringToString(Value));

            // TODO: xxx
            std::abort();
            Backend->SimulateReturnFromFunction(Status);
            })) {
            return false;
        }
    }

    for (const auto offset : PfnRegGetValueW) {
        if (!g_Backend->SetBreakpoint(Gva_t(offset), [](Backend_t* Backend) {
            /*LSTATUS RegGetValueW(
              [in]                HKEY    hkey,
              [in, optional]      LPCWSTR lpSubKey,
              [in, optional]      LPCWSTR lpValue,
              [in, optional]      DWORD   dwFlags,
              [out, optional]     LPDWORD pdwType,
              [out, optional]     PVOID   pvData,
              [in, out, optional] LPDWORD pcbData
            );*/
            LSTATUS Status = ERROR_SUCCESS;
            const HANDLE Handle = HANDLE(Backend->GetArg(0));
            Gva_t vaSubKey = Backend->GetArgGva(1);
            Gva_t vaValue = Backend->GetArgGva(2);
            const DWORD Flags = Backend->GetArg(3);
            Gva_t Type = Backend->GetArgGva(4);
            Gva_t Data = Backend->GetArgGva(5);
            Gva_t cbData = Backend->GetArgGva(6);
            std::u16string SubKey;
            std::u16string Value;

            if (vaSubKey != Gva_t(0))
                SubKey = Backend->VirtReadWideString(vaSubKey, 256);

            if (vaValue != Gva_t(0))
                Value = Backend->VirtReadWideString(vaValue, 256);

            RegDebugPrint("KERNELBASE!RegGetValueW(hKey={}, Subkey={}, Value={})\n", fmt::ptr(Handle), u16stringToString(SubKey), u16stringToString(Value));

            DWORD GuestType = 0;
            PVOID GuestData = nullptr;
            DWORD GuestcbData = 0;

            if (cbData != Gva_t(0)) {
                GuestcbData = Backend->VirtRead4(cbData);
            }

            // 
            // Allocate buffer only if the guest caller is not looking for 
            // size. When |Data| is NULL, the API attempts to return the size
            //

            if (Data != Gva_t(0) &&  GuestcbData > 0) {
                GuestData = (void*)malloc(GuestcbData);
                memset(GuestData, 0, GuestcbData);
            }

            if ((Status = g_GuestRegistry._RegGetValue((HKEY)Handle, SubKey, Value, Flags, &GuestType, GuestData, &GuestcbData)) == ERROR_SUCCESS) {
                
                if (Type != Gva_t(0))
                    Backend->VirtWriteStructDirty(Type , &GuestType);
                if (cbData != Gva_t(0))
                    Backend->VirtWriteStructDirty(cbData, &GuestcbData);
                if (Data != Gva_t(0) && GuestData && GuestcbData > 0)
                    Backend->VirtWriteDirty(Data, (uint8_t*)GuestData, GuestcbData);

                RegDebugPrint("\"{}\" exists so get the value \"{}\"\n", u16stringToString(SubKey), u16stringToString(Value));
            }
            else if (Status == ERROR_MORE_DATA) {
                if (cbData != Gva_t(0))
                    Backend->VirtWriteStructDirty(cbData, &GuestcbData);
            }

            //
            // Free up resources
            // 
            
            if (GuestData) {
                free(GuestData);
                GuestData = nullptr;
            }

            Backend->SimulateReturnFromFunction(Status);
            })) {
            return false;
        }
    }

    for (const auto offset : PfnRegCloseKey) {
        if (!g_Backend->SetBreakpoint(Gva_t(offset), [](Backend_t* Backend) {
            /*LSTATUS RegCloseKey(
              [in] HKEY hKey
            );*/
            LSTATUS Status = ERROR_SUCCESS;
            const HANDLE Handle = HANDLE(Backend->GetArg(0));


            RegDebugPrint("KERNELBASE!RegCloseKey(hKey={})\n", fmt::ptr(Handle));
            
            if ((Status = g_GuestRegistry._RegCloseKey((HKEY)Handle)) == ERROR_SUCCESS) {
                RegDebugPrint("Handle {} is closed\n", fmt::ptr(Handle));
            }

            Backend->SimulateReturnFromFunction(Status);
            })) {
            return false;
        }
    }

    //
    // NT registries
    //

    if (!g_Backend->SetBreakpoint("ntdll!NtOpenKey", [](Backend_t* Backend) {
        /*NTSYSAPI NTSTATUS NtOpenKey(
           [out] PHANDLE            KeyHandle,
           [in]  ACCESS_MASK        DesiredAccess,
           [in]  POBJECT_ATTRIBUTES ObjectAttributes
        );*/
        NTSTATUS Status = STATUS_SUCCESS;

        HANDLE HostKeyHandle = NULL;
        Gva_t KeyHandle = Backend->GetArgGva(0);
        const ACCESS_MASK DesiredAccess = Backend->GetArg(1);
        Gva_t ObjectAttributes = Backend->GetArgGva(2);
        HostObjectAttributes_t HostObjectAttributes;
        if (!HostObjectAttributes.ReadFromGuest(Backend,
            ObjectAttributes)) {
            RegDebugPrint("ReadFromGuest failed.\n");
            std::abort();
        }

        RegDebugPrint("NTDLL!NtOpenKey(DesiredAccess={:#x}, KeyName={})\n", DesiredAccess, u16stringToString(HostObjectAttributes.ObjectName()));
        Status = g_GuestRegistry._NtOpenKey(&HostKeyHandle, DesiredAccess, HostObjectAttributes.ObjectAttributes());
        RegDebugPrint("NTDLL!NtOpenKey(DesiredAccess={:#x}, KeyName={}) = {}\n", DesiredAccess, u16stringToString(HostObjectAttributes.ObjectName()), Status);
        Backend->SimulateReturnFromFunction((uint64_t)Status);
		})) {
		return false;
	}

    if (!g_Backend->SetBreakpoint("ntdll!NtQueryKey", [](Backend_t* Backend) {
        /*NTSYSAPI NTSTATUS NtQueryKey(
          [in]            HANDLE                KeyHandle,
          [in]            KEY_INFORMATION_CLASS KeyInformationClass,
          [out, optional] PVOID                 KeyInformation,
          [in]            ULONG                 Length,
          [out]           PULONG                ResultLength
        );*/
        NTSTATUS Status = STATUS_SUCCESS;
        const HANDLE Handle = HANDLE(Backend->GetArg(0));
        const KEY_INFORMATION_CLASS KeyInformationClass = (KEY_INFORMATION_CLASS)Backend->GetArg(1);
        Gva_t KeyInformation = Backend->GetArgGva(2);
        const ULONG Length = Backend->GetArg(3);
        Gva_t ResultLength = Backend->GetArgGva(4);

        RegDebugPrint("NTDLL!NtQueryKey(hKey={}, KeyInformationClass={})\n", fmt::ptr(Handle), KeyInformationClass);

        PVOID GuestKeyInformation = nullptr;
        ULONG GuestResultLength;

        if ((Status = g_GuestRegistry._NtQueryKey(Handle, KeyInformationClass, &GuestKeyInformation, Length, &GuestResultLength)) == STATUS_SUCCESS) {

            if (KeyInformation != Gva_t(0) && GuestKeyInformation && GuestResultLength > 0)
                Backend->VirtWriteDirty(KeyInformation, (uint8_t*)GuestKeyInformation, GuestResultLength);

            if (ResultLength != Gva_t(0) && GuestResultLength > 0)
                Backend->VirtWriteStructDirty(ResultLength, &GuestResultLength);
        }
        else if (Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL) {

            if (ResultLength != Gva_t(0) && GuestResultLength > 0)
                Backend->VirtWriteStructDirty(ResultLength, &GuestResultLength);
        }

        Backend->SimulateReturnFromFunction(Status);

        })) {
        return false;
    }

    if (!g_Backend->SetBreakpoint("ntdll!NtQueryValueKey", [](Backend_t* Backend) {
        /*NTSYSAPI NTSTATUS NtQueryValueKey(
			 [in]            HANDLE                      KeyHandle,
             [in]            PUNICODE_STRING             ValueName,
             [in]            KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
             [out, optional] PVOID                       KeyValueInformation,
             [in]            ULONG                       Length,
             [out]           PULONG                      ResultLength
        );*/
		NTSTATUS Status = STATUS_SUCCESS;
		const HANDLE Handle = HANDLE(Backend->GetArg(0));
        Gva_t ValueName = Backend->GetArgGva(1);
		const KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass = (KEY_VALUE_INFORMATION_CLASS)Backend->GetArg(2);
		Gva_t KeyValueInformation = Backend->GetArgGva(3);
		const ULONG Length = Backend->GetArg(4);
		Gva_t ResultLength = Backend->GetArgGva(5);

		auto HostValueName = new UNICODE_STRING;
		if (!HostValueName) {
			RegDebugPrint("Could not allocate a UNICODE_STRING.\n");
            std::abort();
		}

		//
		// Read the ValueName.
		//

		Backend->VirtReadStruct(ValueName, HostValueName);

		//
		// Allocate memory for the UNICODE_STRING buffer. Note that it is not
		// mandatory to have the buffer NULL terminated. This happens when Length ==
		// MaximumLength.
		//

		const bool NeedsNullByte = HostValueName->MaximumLength == HostValueName->Length;

		//
		// Don't forget here that the Length are not number of char16_t but are
		// buffer size. That is why we need to mulitply `NeedsNullByte` by the size
		// of char16_t.
		//

        HostValueName->MaximumLength += uint64_t(NeedsNullByte) * sizeof(char16_t);

		//
		// Allocate the buffer.
		//

		auto HostValueNameBuffer =
			(char16_t*)new uint8_t[HostValueName->MaximumLength];
		if (!HostValueNameBuffer) {
			RegDebugPrint("Could not allocate the UNICODE_STRING buffer.\n");
            std::abort();
		}

		//
		// Read the UNICODE_STRING buffer.
		//

		const Gva_t Buffer = Gva_t(uint64_t(HostValueName->Buffer));
		Backend->VirtRead(Buffer, (uint8_t*)HostValueNameBuffer, HostValueName->MaximumLength);

		//
		// Fix the null byte if we need to.
		//

		if (NeedsNullByte) {
			const uint64_t NullByteOffset = HostValueName->Length / sizeof(char16_t);
            HostValueNameBuffer[NullByteOffset] = 0;
		}

		RegDebugPrint("NTDLL!NtQueryValueKey(hKey={}, ValueName={}, KeyInformationClass={})\n", fmt::ptr(Handle), u16stringToString(HostValueNameBuffer), KeyValueInformationClass);

		PVOID GuestKeyInformation = nullptr;
        ULONG GuestResultLength = 0;
        __debugbreak();
		if ((Status = g_GuestRegistry._NtQueryValueKey(Handle, HostValueName, KeyValueInformationClass, &GuestKeyInformation, Length, &GuestResultLength)) == STATUS_SUCCESS) {

			if (KeyValueInformation != Gva_t(0) && GuestKeyInformation && GuestResultLength > 0)
				Backend->VirtWriteDirty(KeyValueInformation, (uint8_t*)GuestKeyInformation, GuestResultLength);

			if (ResultLength != Gva_t(0) && GuestResultLength > 0)
				Backend->VirtWriteStructDirty(ResultLength, &GuestResultLength);
		}
		else if (Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL) {

			if (ResultLength != Gva_t(0) && GuestResultLength > 0)
				Backend->VirtWriteStructDirty(ResultLength, &GuestResultLength);
		}

		Backend->SimulateReturnFromFunction(Status);
        })) {
        return false;
    }


  return true;
}

RegHandleTable_t g_RegHandleTable;
GuestRegsitry_t g_GuestRegistry;