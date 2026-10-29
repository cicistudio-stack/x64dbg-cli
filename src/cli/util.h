#pragma once

#include <string>
#include <vector>

namespace cli
{
// "0x" + 16 lowercase hex digits.
std::string hexAddr(unsigned long long v);
// "0x" + minimal lowercase hex, used when a number is spliced into a native command line (radix rule).
std::string hexArg(long long v);

std::string trim(const std::string & s);
std::string lower(const std::string & s);
bool startsWith(const std::string & s, const char* prefix);

// The state machine of the core's cmdsplit (command.cpp): splits on ';' outside double quotes.
// Segments are returned untrimmed, empty segments are dropped.
std::vector<std::string> splitSemicolon(const std::string & s);

// Shell-like tokenizer of the text mode: double quotes group, a backslash is literal unless it directly
// precedes a double quote (then the pair is a literal quote). Returns false on an unterminated quote.
bool tokenize(const std::string & s, std::vector<std::string> & out, std::string & error);

// Strips HTML tags (<br> becomes a newline) and decodes the entities &lt; &gt; &amp; &quot; &nbsp;.
std::string stripHtml(const std::string & s);

// Text renderer rule: CRLF -> LF, every other byte below 0x20 (except LF, TAB) and 0x7f becomes \xNN.
std::string escapeControlText(const std::string & s);

// CommandLineToArgvW compatible quoting of the target arguments (design 8.1).
std::string joinTargetArgs(const std::vector<std::string> & args);

// Parses a decimal or 0x-prefixed hexadecimal non-negative integer. Returns false on any other text.
bool parseInteger(const std::string & s, long long & out);

// First word of a native segment (up to the first space, tab or comma), as typed.
std::string firstWord(const std::string & segment);

// Escapes an argument for insertion between double quotes in a native command (the core's Command::Escape rule):
// a double quote or '{' gets a backslash; backslash runs before a quote or at the end are doubled.
std::string commandEscape(const std::string & s);

std::string utf8Of(const wchar_t* w);
std::wstring wideOf(const std::string & s);
}
