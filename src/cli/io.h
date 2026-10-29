#pragma once

#include <Windows.h>

#include <functional>
#include <string>

namespace cli
{
namespace io
{
// Duplicates the real stdin/stdout/stderr into private handles and points the process-level standard
// handles and the CRT streams at NUL, so no stray print can reach the protocol stream.
void init(bool verbose);
// Restores the console code pages (if they were changed).
void restore();

// Starts the Writer thread. onFatal(code) is called (once) when the consumer is gone or stalled.
void startWriter(std::function<void(const char* code)> onFatal);
// Queues one whole protocol message (it must already end with '\n'). Never blocks on the consumer.
bool writeProtocol(std::string message);
// Emergency path: the line goes to the front of the queue; waits at most 250 ms for the queue to empty.
void writeFatal(const std::string & line);
// Waits at most ms for the outbound queue to become empty. Returns false when data remains.
bool drain(int ms);
bool outputLost();
// Pending bytes in the outbound queue (for tests).
size_t pendingBytes();

// Diagnostics on the real stderr (only used at -v).
void diag(const std::string & text, bool force = false);
bool verbose();

// stdin
bool stdinIsConsole();
class LineReader
{
public:
    enum Result
    {
        Line,
        TooLong,
        Eof,
        Cancelled
    };
    // Reads one line (without the line terminator). Strips a leading UTF-8 BOM on the first line.
    // Lines above maxBytes are discarded (the result is TooLong).
    Result read(std::string & line, size_t maxBytes = 1u << 20);
    // Set by the owner; checked before each ReadFile.
    std::function<bool()> shouldStop;
    std::function<void()> beforeRead;

private:
    std::string buf_;
    bool first_ = true;
    bool eof_ = false;
    bool discarding_ = false;
};
}
}
