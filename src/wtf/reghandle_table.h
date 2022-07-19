// @x9090 - April 25 2022
#pragma once
#include "globals.h"
#include "platform.h"
#include "restorable.h"
#include <cstdint>
#include <fmt/format.h>
#include <unordered_map>
#include <unordered_set>

#ifdef REG_HANDLETABLE_LOGGING_ON
#define HandleTableDebugPrint(Format, ...)                                     \
  fmt::print("reghandletable: " Format, __VA_ARGS__)
#else
#define HandleTableDebugPrint(Format, ...) /* nuthin */
#endif

class RegHandleTable_t : public Restorable {
	uint64_t LatestGuestHandle_;
	uint64_t SavedLatestGuestHandle_;

	//
	// This maps a guest handle to a host handle.
	//

	std::unordered_map<HANDLE, HANDLE> HandleMapping_;

	//
	// Same as above.
	//

	std::unordered_map<HANDLE, HANDLE> SavedHandleMapping_;

	//
	// This is a list of pseudo handles; we need to guarantee that
	// AllocateGuestHandle doesn't generate one of them.
	//

	std::unordered_set<uint32_t> PseudoHandles_;

	//
	// This is a list of handles that we don't want the AllocateGuestHandle
	// function to generate.
	//

	std::unordered_set<HANDLE> ReservedHandles_;

public:
	//
	// This is the last guest handle we can generate. The allocator go from there
	// downwards.
	//

	static const uint64_t LastGuestHandle = 0x7ffffffffffffffeULL;

	//
	// ctor.
	//

	RegHandleTable_t()
		: LatestGuestHandle_(LastGuestHandle),
		SavedLatestGuestHandle_(LastGuestHandle) {

		//
		// Do not clash with the pseudo handles (kernelbase!GetFileType uses them
		// for example).
		//

		PseudoHandles_.emplace(STD_INPUT_HANDLE);
		PseudoHandles_.emplace(STD_OUTPUT_HANDLE);
		PseudoHandles_.emplace(STD_ERROR_HANDLE);
	}

	void Save() override {

		//
		// Save our state.
		//

		SavedLatestGuestHandle_ = LatestGuestHandle_;
		SavedHandleMapping_ = HandleMapping_;
	}

	void Restore() override {

		//
		// Walk the handles that haven't been saved and close them all.
		//

		for (const auto& [GuestHandle, HostHandle] : HandleMapping_) {
			if (SavedHandleMapping_.contains(GuestHandle)) {
				continue;
			}

			HandleTableDebugPrint("FYI {} hasn't been closed.\n", GuestHandle);
			CloseGuestHandle(HostHandle);
		}

		//
		// Restore our state.
		//

		LatestGuestHandle_ = SavedLatestGuestHandle_;
		HandleMapping_ = SavedHandleMapping_;
	}

	//
	// Check if guest handle exists
	//

	bool Has(const HANDLE Handle) {
		return HandleMapping_.contains(Handle);
	}

	HANDLE AllocateGuestHandle() {
		HANDLE GuestHandle = nullptr;
		while (1) {
			GuestHandle = HANDLE(LatestGuestHandle_);
			const uint32_t LowerDword = uint32_t(LatestGuestHandle_);

			LatestGuestHandle_--;
			if (PseudoHandles_.contains(LowerDword) ||
				ReservedHandles_.contains(GuestHandle)) {
				continue;
			}

			break;
		}

		return GuestHandle;
	}

	bool AddHandle(const HANDLE GuestHandle, const HANDLE HostHandle) {
		//
		// Add a mapping between a guest handle and a host handle.
		//

		const bool Inserted = HandleMapping_.emplace(GuestHandle, HostHandle).second;
		
		if (!Inserted) {
			fmt::print("Guest handle already exist?\n");
			__debugbreak();
		}

		return Inserted;
	}

	bool CloseGuestHandle(const HANDLE GuestHandle) {

		//
		// Check if we know the handle.
		//

		if (!HandleMapping_.contains(GuestHandle)) {
			return false;
		}

		//
		// If this was a tracked handle (ghost or not), we can now remove it from
		// our state.
		//

		HandleMapping_.erase(GuestHandle);

		return true;
	}

	HANDLE GetHostHandle(const HANDLE GuestHandle) {

		if (!HandleMapping_.contains(GuestHandle)) {
			return nullptr;
		}

		return HandleMapping_.at(GuestHandle);
	}

	bool KnownRootKey(const HANDLE Handle) {

		if (Handle == HKEY_CLASSES_ROOT ||
			Handle == HKEY_CURRENT_CONFIG ||
			Handle == HKEY_CURRENT_USER ||
			Handle == HKEY_LOCAL_MACHINE ||
			Handle == HKEY_USERS)
			return true;
		else
			return false;
	}
};

//
// The global handle table.
//

extern RegHandleTable_t g_RegHandleTable;