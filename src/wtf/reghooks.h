// Axel '0vercl0k' Souchet - March 27 2020
#pragma once

#include "globals.h"
#include "reghandle_table.h"
#include <cstdio>
#include <fmt/format.h>
#include <winreg.h>

constexpr bool RegHooksLoggingOn = true;

template <typename... Args_t>
void RegDebugPrint(const char* Format, const Args_t &...args) {
	if constexpr (RegHooksLoggingOn) {
		fmt::print("reg: ");
		fmt::print(Format, args...);
	}
}

class GuestRegsitry_t : public Restorable {
	std::unordered_map<HANDLE, std::u16string> GuestRegistries_;

public:

	~GuestRegsitry_t() {};

	//
	// ctor.
	//

	GuestRegsitry_t() {};

	//
	// Save the state of the reg handle table. This is invoked by the handle table
	// itself.
	//

	void Save() override {};

	//
	// Restore the state of the reg handle table. This is invoked by the handle
	// table itself.
	//

	void Restore() override {};

	//
	// Associate a guest handle and a guest/host registry.
	//

	bool AddHandle(const HANDLE GuestHandle, const std::u16string Registry) {
		const auto Res = GuestRegistries_.emplace(GuestHandle, Registry);
		const bool Inserted = Res.second;

		if (!Inserted) {
			fmt::print("Handle {} already mapped {}?\n", fmt::ptr(GuestHandle), u16stringToString(Registry));
			__debugbreak();
		}

		return Inserted;
	};

	//
	// Does this file exists in our world?
	//

	bool Exists(const std::u16string& Registry) {};
	
	//
	// RegOpenKeyExA/RegOpenKeyExW hook
	//

	LSTATUS _RegOpenKeyEx(HKEY hRootKey, const std::u16string Registry, PHKEY phkResult) {

		std::u16string RootKey = get_rootkey(Registry);
		std::u16string SubKey = get_subkey(Registry);
		HKEY hKey = HKEY_LOCAL_MACHINE;
		LSTATUS status;

		if (RootKey == u"HKLM")
			hKey = HKEY_LOCAL_MACHINE;
		else if (RootKey == u"HKCR")
			hKey = HKEY_CLASSES_ROOT;
		else if (RootKey == u"HKCU")
			hKey = HKEY_CURRENT_USER;
		else if (RootKey == u"HKU")
			hKey = HKEY_USERS;
		else {
			hKey = hRootKey;
			SubKey = Registry;

			//
			// Redirect GuestRootKey to HostRootKey
			// if root key is not the known RootKeys
			//

			HKEY result;

			if (g_RegHandleTable.KnownRootKey(hKey)) {
				hKey = hRootKey;
			}else if (g_RegHandleTable.Has(hKey)) {

				HKEY rootkey = (HKEY)g_RegHandleTable.GetHostHandle(hKey);

				if (!rootkey) {
					fmt::print("reg: GuestHandle {} is not mapped yet?\n", fmt::ptr(hKey));
					__debugbreak();
				}

				hKey = rootkey;
			}
			//
			// We need to retrieve the root key path 
			// and get the root key handle if
			// the root key is not available yet
			//
			else if (GuestRegistries_.contains(hKey)) {

				std::u16string rootkey = GuestRegistries_.at(hKey);
				if ((status = _RegOpenKeyEx(hKey, rootkey.c_str(), &result)) != ERROR_SUCCESS) {
					fmt::print("reg: Failed to open root key: {}\n", u16stringToString(rootkey));
					//__debugbreak();
				}

				//HANDLE GuestHandle = g_RegHandleTable.AllocateGuestHandle();
				g_RegHandleTable.AddHandle(hKey, result);
				hKey = result;
			}
		}

		if ((status = RegOpenKeyW(hKey, (LPCWSTR)SubKey.c_str(), phkResult)) != ERROR_SUCCESS) {
			fmt::print("reg: Failed to open key: {}\n", u16stringToString(SubKey));
			//__debugbreak();
		}
		else {
			//RegCloseKey(*phkResult);
			//*phkResult = (HKEY)g_RegHandleTable.AllocateGuestHandle();
		}

		return status;
	};

	//
	// RegGetValueA/RegGetValueW hook
	//

	LSTATUS _RegGetValue(HKEY hRootKey, const std::u16string SubKey, const std::u16string Value, DWORD Flags, DWORD *Type, PVOID Data, DWORD *cbData) {

		std::u16string RootKey_ = get_rootkey(SubKey);
		std::u16string SubKey_ = get_subkey(SubKey);
		HKEY hKey = HKEY_LOCAL_MACHINE;
		LSTATUS status;

		if (RootKey_ == u"HKLM")
			hKey = HKEY_LOCAL_MACHINE;
		else if (RootKey_ == u"HKCR")
			hKey = HKEY_CLASSES_ROOT;
		else if (RootKey_ == u"HKCU")
			hKey = HKEY_CURRENT_USER;
		else if (RootKey_ == u"HKU")
			hKey = HKEY_USERS;
		else {
			hKey = hRootKey;
			SubKey_ = SubKey;
		}

		//
		// Easiest case - it is a known root key
		//

		if (g_RegHandleTable.KnownRootKey(hKey)) {
			hKey = hRootKey;
		}
		//
		// Determine if it is our previously seen root key
		//
		else if (g_RegHandleTable.Has(hKey)) {

			HKEY rootkey = (HKEY)g_RegHandleTable.GetHostHandle(hKey);

			if (!rootkey) {
				fmt::print("reg: GuestHandle {} is not mapped yet?\n", fmt::ptr(hKey));
				__debugbreak();
			}

			hKey = rootkey;
		}
		else {
			fmt::print("reg: Unknown handle {}\n", fmt::ptr(hKey));
			__debugbreak();
		}


		if ((status = RegGetValueW(hKey, (LPCWSTR)SubKey.c_str(), (LPCWSTR)Value.c_str(), Flags, Type, Data, cbData)) != ERROR_SUCCESS) {
			fmt::print("reg: Failed to get value \"{}\" from key \"{}\" ({:#x})\n", u16stringToString(Value), u16stringToString(SubKey), status);	
			//__debugbreak();
		}

		return status;
	};

	//
	// RegCloseKey hook
	// 
	
	LSTATUS _RegCloseKey(HKEY GuestHandle){

		LSTATUS status = ERROR_SUCCESS;
		HKEY HostHandle;

		//
		// Determine if it is our previously seen root key
		//
		if (g_RegHandleTable.Has(GuestHandle)) {

			HostHandle = (HKEY)g_RegHandleTable.GetHostHandle(GuestHandle);

			if (!HostHandle) {
				fmt::print("reg: GuestHandle {} is not mapped yet?\n", fmt::ptr(GuestHandle));
				__debugbreak();
			}
		}
		else {
			fmt::print("reg: Unknown handle {}\n", fmt::ptr(GuestHandle));
			__debugbreak();
		}

		if ((status = RegCloseKey(HostHandle)) != ERROR_SUCCESS) {
			fmt::print("reg: Failed to close key {:#x}:{:#x}\n", fmt::ptr(GuestHandle), fmt::ptr(HostHandle));
		}
		else if (status == ERROR_SUCCESS){
			g_RegHandleTable.CloseGuestHandle(GuestHandle);
		}

		return status;
	};

	
	//
	// ntdll!NtOpenKey hook
	//

	NTSTATUS _NtOpenKey(PHANDLE HostHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes) {

		NTSTATUS Status = NtOpenKey(HostHandle, DesiredAccess, ObjectAttributes);
		
		if (NT_SUCCESS(Status)) {
			HANDLE GuestHandle = g_RegHandleTable.AllocateGuestHandle();
			RegDebugPrint("KeyName={} => {}:{}\n", DesiredAccess, u16stringToString(ObjectAttributes->ObjectName->Buffer), fmt::ptr(GuestHandle), fmt::ptr(*HostHandle));
			g_RegHandleTable.AddHandle(GuestHandle, *HostHandle);
		}

		return Status;
	}

	//
	// ntdll!NtQueryKey hook
	//

	NTSTATUS _NtQueryKey(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID *KeyInformation, ULONG Length, ULONG *ResultLength) {
		HANDLE KeyHandle_;


		//
		// Determine if it is our previously seen root key
		//
		if (g_RegHandleTable.Has(KeyHandle)) {

			KeyHandle_ = (HKEY)g_RegHandleTable.GetHostHandle(KeyHandle);

			if (!KeyHandle_) {
				fmt::print("reg: GuestHandle {} is not mapped yet?\n", fmt::ptr(KeyHandle_));
				__debugbreak();
			}
		}
		else {
			fmt::print("reg: Unknown handle {}\n", fmt::ptr(KeyHandle));
			__debugbreak();
		}

		*KeyInformation = (void*)malloc(Length);
		memset(*KeyInformation, 0, Length);
		return NtQueryKey(KeyHandle_, KeyInformationClass, *KeyInformation, Length, ResultLength);

	}

	//
	// ntdll!NtQueryValueKey hook
	//

	NTSTATUS _NtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID* KeyValueInformation, ULONG Length, ULONG* ResultLength) {
		HANDLE KeyHandle_;

		//
		// Determine if it is our previously seen root key
		//
		if (g_RegHandleTable.Has(KeyHandle)) {

			KeyHandle_ = (HKEY)g_RegHandleTable.GetHostHandle(KeyHandle);

			if (!KeyHandle_) {
				fmt::print("reg: GuestHandle {} is not mapped yet?\n", fmt::ptr(KeyHandle_));
				__debugbreak();
			}
		}
		else {
			fmt::print("reg: Unknown handle {}\n", fmt::ptr(KeyHandle));
			__debugbreak();
		}

		*KeyValueInformation = (void*)malloc(Length);
		memset(*KeyValueInformation, 0, Length);
		return NtQueryValueKey(KeyHandle_, ValueName, KeyValueInformationClass, *KeyValueInformation, Length, ResultLength);

	}


private:
	inline std::u16string get_rootkey(const std::u16string& reg)
	{
		unsigned int i = reg.find(u"\\");
		if (i == std::u16string::npos)
		{
			return reg;
		}
		else
		{
			return reg.substr(0, i);
		}
	}

	inline std::u16string get_subkey(const std::u16string& reg)
	{
		unsigned int i = reg.find(u"\\");
		if (i == std::u16string::npos)
		{
			return reg;
		}
		else
		{
			return reg.substr(i + 1);
		}
	}
};

bool SetupRegistryHooks();

extern GuestRegsitry_t g_GuestRegistry;