// Axel '0vercl0k' Souchet - April 5 2020
#include "subcommands.h"
#include "client.h"
#include "corpus.h"
#include "dirwatch.h"
#include "mutator.h"
#include "server.h"
#include "targets.h"
#include <chrono>
#include <fmt/format.h>
#include <random>

namespace fs = std::filesystem;
namespace chrono = std::chrono;

int RunSubcommand(const Options_t &Opts, const Target_t &Target,
                  const CpuState_t &CpuState) {
  const RunOptions_t &RunOpts = Opts.Run;
  std::vector<fs::path> Testcases;

  //
  // If the input flag is a folder, then we enumerate the files inside it.
  //

  if (fs::is_directory(RunOpts.InputPath)) {
    const fs::directory_iterator DirIt(RunOpts.InputPath);
    for (const auto &DirEntry : DirIt) {
      Testcases.emplace_back(DirEntry);
    }
  } else {
    Testcases.emplace_back(RunOpts.InputPath);
  }

  //
  // Explicitly enable context switching
  // 
  if (Opts.Run.AllowCr3) g_Backend->SetAllowContextSwitch();

  //
  // Initialize the fuzzer.
  //

  if (!Target.Init(Opts, CpuState)) {
    fmt::print("Could not initialize target fuzzer.\n");
    return EXIT_FAILURE;
  }

  //
  // We only display the run stats if we have a single input, otherwise it looks
  // awkward.
  //

  const bool PrintRunStats = Testcases.size() == 1 && RunOpts.Runs == 1;
  for (const fs::path &Testcase : Testcases) {

	uint64_t StartingAddress = 0;
	if (RunOpts.StartingAddress.size() > 0) {
		if (RunOpts.StartingAddress.find("0x") == 0 || RunOpts.StartingAddress.find("0X") == 0)
			StartingAddress = _strtoui64(RunOpts.StartingAddress.substr(2).c_str(), nullptr, 16);
		else
			StartingAddress = _strtoui64(RunOpts.StartingAddress.c_str(), nullptr, 16);
	}
    //
    // Initialize the trace file if the user wants to.
    //

    if (!RunOpts.BaseTracePath.empty()) {
      const std::string TraceName = StartingAddress == 0 ? 
          fmt::format("{}.trace", Testcase.filename().string()) : fmt::format("{}_{}.trace", Testcase.filename().string(), RunOpts.StartingAddress);
      const fs::path TestcaseTracePath(RunOpts.BaseTracePath / TraceName);

      //
      // If the file already exists, then just skip it.
      //

      if (fs::exists(TestcaseTracePath)) {
        fmt::print("Skipping {} as it already exists.\n",
                   TestcaseTracePath.string());
        continue;
      }

      fmt::print("Trace file {}\n", TestcaseTracePath.string());
      if (!g_Backend->SetTraceFile(TestcaseTracePath, RunOpts.TraceType, StartingAddress)) {
        fmt::print("SetTraceFile failed.\n");
        return EXIT_FAILURE;
      }
    }

    //
    // Read the input file.
    //

    fmt::print("Running {}\n", Testcase.string());
    size_t BufferSize = 0;
    const auto Buffer = ReadFile(Testcase, BufferSize);
    const std::span<uint8_t> BufferSpan(Buffer.get(), BufferSize);
    for (uint64_t RunIdx = 0; RunIdx < RunOpts.Runs; RunIdx++) {
      TestcaseResult_t Res =
          RunTestcaseAndRestore(Target, CpuState, BufferSpan, PrintRunStats);
    }
  }

  return EXIT_SUCCESS;
}

int FuzzSubcommand(const Options_t &Opts, const Target_t &Target,
                   const CpuState_t &CpuState) {
  return Client_t(Opts).Run(Target, CpuState);
}

int MasterSubcommand(const Options_t &Opts, const Target_t &Target) {
  return Server_t(Opts.Master).Run(Target);
}