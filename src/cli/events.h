#pragma once

#include <string>
#include <vector>

#include "json.h"

namespace cli
{
// Inputs of the pause-reason attribution (design 7.5). Pure data, so the algorithm is unit-testable.
struct AttribInput
{
    std::vector<Json> window;   // events with lastRunningSeq < seq <= pausedSeq (all types)
    std::vector<Json> trailing; // stepped / exception events behind the paused event (no resumed in between)
    unsigned long long cip = 0;
    bool lastExcValid = false;
    unsigned long long lastExcCode = 0;
    long long lastExcStamp = 0;
    long long lastRunningSeq = 0;
    long long pausedSeq = 0;
    std::string lastResumeName; // canonical name, lowercase
    // Settings of the "Events" section that make the core pause on thread/DLL/debug-string events.
    bool threadStart = false, threadEnd = false, dllLoad = false, dllUnload = false, debugStrings = false;
};

// Returns the `state.stop` object: {reason, [bp], [hint], [exception]}.
Json attribute(const AttribInput & in);

// True when the window holds at least one possible cause event (step 1 of the attribution).
bool windowHasCause(const AttribInput & in);

// Canonical (lowercase) name sets of design 7.4 / 7.5.
bool isFinisher(const std::string & lowerCanon);
bool isResumeClass(const std::string & lowerCanon);
bool isStepGuard(const std::string & lowerCanon);
bool isCountForm(const std::string & lowerCanon);

// Parses "0x..." produced by hexAddr. Returns 0 on failure.
unsigned long long parseHexAddr(const std::string & s);
}
