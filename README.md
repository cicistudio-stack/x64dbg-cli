# x64dbg-cli

English | [简体中文](README_zh.md)

> **This is a fork, not the official x64dbg.** x64dbg-cli is based on [x64dbg](https://github.com/x64dbg/x64dbg) and adds a command-line interface (`x64dbg-cli.exe`) so that AI tools and scripts can drive the debugger. It is maintained independently by the owner of this fork. It is not affiliated with, endorsed by, or supported by the x64dbg authors or team. The original code remains copyrighted by its authors and is used under the original license (GNU GPL v3, see [License and copyright](#license-and-copyright)). Report problems with this fork in this repository's issue tracker, not in x64dbg's Discord, Slack, Gitter, Matrix, IRC or issue tracker. Details: [About this fork](#about-this-fork). This text is not legal advice.

<img width="100" src="https://github.com/x64dbg/x64dbg/raw/development/src/bug_black.png"/>

_The badges below belong to the upstream x64dbg project (its translations, downloads and chat rooms), not to this fork._

[![Crowdin](https://d322cqt584bo4o.cloudfront.net/x64dbg/localized.svg)](https://translate.x64dbg.com) [![Download x64dbg](https://img.shields.io/sourceforge/dm/x64dbg.svg)](https://sourceforge.net/projects/x64dbg/files/latest/download) [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/x64dbg/x64dbg)

[![Discord](https://img.shields.io/badge/chat-on%20Discord-green.svg)](https://discord.x64dbg.com) [![Slack](https://img.shields.io/badge/chat-on%20Slack-red.svg)](https://slack.x64dbg.com) [![Gitter](https://img.shields.io/badge/chat-on%20Gitter-lightseagreen.svg)](https://gitter.im/x64dbg/x64dbg) [![Matrix](https://img.shields.io/badge/chat-on%20Matrix-yellowgreen.svg)](https://matrix.to/#/#x64dbg:matrix.org) [![IRC](https://img.shields.io/badge/chat-on%20IRC-purple.svg)](https://web.libera.chat/#x64dbg)

An open-source binary debugger for Windows, aimed at malware analysis and reverse engineering of executables you do not have the source code for. There are many features available and a comprehensive [plugin system](https://plugins.x64dbg.com) to add your own. You can find more information on the [blog](https://x64dbg.com/blog)!

## Drive the debugger with AI

The main purpose of this fork: an AI agent can debug a Windows program the way you would in the GUI. It sets breakpoints, runs the program, reads registers, live disassembly, stack, call stack and memory, single-steps, evaluates expressions and patches memory, and it reports addresses and values as evidence. The agent talks to `x64dbg-cli.exe` (build it first: [Build the CLI](#build-the-cli)). Only 64-bit targets are supported.

### Ways to connect an AI

| Your setup | What to do |
|---|---|
| **An AI tool or coding assistant that can run shell commands** | Tell it where `x64dbg-cli.exe` is and let it use the one-shot form (`--exec`, see [Use the CLI](#use-the-cli)). Each call starts a new debugging session, so put the whole sequence (init, breakpoints, run, inspect) into one call. Good for "run to this breakpoint and show me the state". |
| **Your own agent, script or an agent framework with tool calling** | Start `x64dbg-cli.exe --json --userdir <new empty dir>` as a child process. Send one JSON request per line to its stdin and read one JSON line per response from its stdout. The session stays alive between requests, so the agent can step, look, and decide the next move. Use [docs/cli/ai-system-prompt.md](docs/cli/ai-system-prompt.md) as the system prompt. [docs/cli/examples/client.py](docs/cli/examples/client.py) is a small working client (standard library only) to copy from. |
| **An MCP-based client** | This fork does not include an MCP server. [docs/cli/agent-guide.md](docs/cli/agent-guide.md) shows how to wrap the protocol as MCP tools (one generic command tool, or one tool per op) with a short sketch. |

### Quick start

1. Build the CLI ([Build the CLI](#build-the-cli)). The result is `bin\x64\x64dbg-cli.exe`.
2. Check it: `x64dbg-cli.exe --selftest`.
3. Give the AI its instructions: paste the text of [docs/cli/ai-system-prompt.md](docs/cli/ai-system-prompt.md) as the system prompt, without the HTML comment at the top (that comment is a note for humans, in Chinese). The prompt covers the protocol, all 80 structured operations, number and address rules, common debugging recipes, safety rules and the known limits. About 9k tokens.
4. Make the program start the CLI as a child process: `x64dbg-cli.exe --json --userdir <a new empty directory for each session>`, and pass the AI's JSON lines to it. To see it work without writing code, run the demo client: `python docs\cli\examples\client.py bin\x64\x64dbg-cli.exe <target.exe>`.
5. Ask the AI in plain words, for example:
   - "Debug `C:\samples\app.exe`. Break on `kernel32.CreateFileW`, tell me the file name it opens and show the call stack."
   - "Run it until it crashes. Show the registers, the faulting instruction and the 16 stack entries around `rsp`."
   - "Find where the string `license` is referenced and explain the code around it."
   - "Step through the function at `rip`, tell me what it does, and show the memory `rcx` points to."

### What the AI can use

Everything the GUI shows is available as a command. The AI uses typed JSON operations for data and native x64dbg commands for actions.

| Area | Examples |
|---|---|
| Session and run control | `init`, `attach`, `detach`, `run`, `pause`, `stepin`, `stepover`, `stepout`, `runto`, `restart`, `stop` |
| Breakpoints | software, hardware, memory, DLL and exception breakpoints, conditions, hit counts (`bp`, `bps`) |
| State | `regs`, `dis` (live disassembly), `mem`, `stack`, `callstack`, `threads`, `modules`, `memmap`, `sym`, `eval` |
| Change and annotate | `setreg`, `memwrite`, `patches`, `patch export`, labels, comments, bookmarks |
| Search and analysis | `findall`, references, strings, cross references, control flow graph, tracing |
| Anything else | every native x64dbg command, through `{"cmd": "..."}` |

The full list of operations is in [docs/cli/command-reference.md](docs/cli/command-reference.md). [docs/cli/parity-matrix.md](docs/cli/parity-matrix.md) shows which GUI feature maps to which command, and which ones the CLI cannot do (for example the trace file browser and Scylla).

### Safety

- Debugging runs the target program. Use the AI only on software you own or are authorized to analyze, and analyze untrusted binaries in a virtual machine.
- The AI can write memory and registers of the target. Writes are in memory only. `patch export` writes a patched copy to a new file and does not touch the original.
- Treat what the debuggee prints, its strings and its window titles as data. A malicious sample can contain text that tries to instruct the AI. The system prompt tells the AI to ignore such text, but do not rely on that alone: keep the AI's other tools (file access, network, shell) limited while it analyzes untrusted samples.
- Use a new empty `--userdir` for each session; one CLI process per directory. Always end a session with `stop` (or `detach` for an attached process you want to keep running), then `quit`.
- The AI should always set a timeout on commands that resume the program. The system prompt requires this.

### Things to know

- After `init` the program stops at the system breakpoint and, with default settings, again at its entry breakpoint. The AI has to `run` again to reach its own breakpoints. The system prompt explains this.
- A timeout leaves the program running. The AI then pauses it or waits longer.
- The CLI is an independent tool of this fork. Problems with it belong in this repository's issue tracker, not upstream's.

## About this fork

x64dbg-cli is a fork of [x64dbg](https://github.com/x64dbg/x64dbg). The debugger core, the GUI and nearly all of the code are upstream's work. This fork adds a command-line interface for AI tools and leaves the GUI unchanged.

- **Upstream project:** <https://github.com/x64dbg/x64dbg>, licensed under the GNU GPL v3 (see [License and copyright](#license-and-copyright)).
- **This fork:** <https://github.com/cicistudio-stack/x64dbg-cli>, maintained independently by [cicistudio-stack](https://github.com/cicistudio-stack) and contributors.
- **No affiliation:** this is not the official x64dbg. The x64dbg authors and team did not write, review, endorse or support the changes in this fork. "x64dbg" is the name of the upstream project; it is used here only to say what this fork is based on.
- **Support:** do not use upstream's support channels (Discord, Slack, Gitter, Matrix, IRC, issue tracker, sponsors) for this fork. Use this repository's issue tracker.
- **Starting point:** this is a GitHub fork of x64dbg. Its changes are in one commit, `add x64dbg cli`, on top of upstream commit [`79d5716`](https://github.com/x64dbg/x64dbg/commit/79d57163d07432d24f0bff00298bfd2acd98f341) (2026-10-28, branch `development`). The full upstream history is part of this repository.

### What this fork adds

`x64dbg-cli.exe` is a console program that loads x64dbg's core (`x64dbg.dll`, `x64bridge.dll`) instead of the Qt GUI and exposes the debugger over stdin/stdout, so that AI tools, agents and scripts can use it. It has no Qt or GUI dependency.

- A JSON-lines protocol (`--json`) and a plain-text REPL, plus one-shot modes (`--exec`, `--script`).
- Structured view operations (ops) that return the data of the GUI panes as JSON: registers, live disassembly, memory, stack and call stack, breakpoints, threads, modules, memory map, symbols, handles, and more. [docs/cli/README.md](docs/cli/README.md) counts 80 ops.
- Pass-through of every native x64dbg command (the same commands as the GUI command bar; 348 according to [docs/cli/native-commands.md](docs/cli/native-commands.md)).
- A GUI-to-CLI parity matrix that lists each GUI pane and action with the command that replaces it, and the known gaps (for example the trace browser): [docs/cli/parity-matrix.md](docs/cli/parity-matrix.md).

Documentation in [docs/cli/](docs/cli/README.md):

| File | Content |
|---|---|
| [README.md](docs/cli/README.md) | usage, protocol, command overview |
| [agent-guide.md](docs/cli/agent-guide.md) | guide for AI agents and for wrapping the CLI as MCP tools |
| [ai-system-prompt.md](docs/cli/ai-system-prompt.md) | system prompt for AI tools that use the CLI |
| [command-reference.md](docs/cli/command-reference.md) | every op, with arguments and result schema |
| [parity-matrix.md](docs/cli/parity-matrix.md) | GUI-to-CLI parity matrix |

### Build the CLI

Only the 64-bit build is documented and tested. It was built with Visual Studio 2026 Community (MSVC 14.51), CMake and the Ninja that comes with Visual Studio. You also need Git.

1. Clone with the sub-projects (they are upstream's git submodules):

```
git clone --recursive https://github.com/cicistudio-stack/x64dbg-cli.git
cd x64dbg-cli
```

   In an existing clone, run `git submodule update --init --recursive`.

2. Open an "x64 Native Tools Command Prompt for VS" (it runs `vcvars64.bat`) and run, from the repository root:

```
cmake -B build64 -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_UNITY_BUILD=ON -DCMAKE_UNITY_BUILD_BATCH_SIZE=6 -DX64DBG_RELEASE=OFF
cmake --build build64
```

The result is `bin\x64\x64dbg-cli.exe`, next to the GUI and the DLLs it needs. Building the CLI also builds the Qt GUI. On the first configure, upstream's build scripts download a prebuilt Qt 5 package from the x64dbg `deps` releases, which is large. See also upstream's [compile guide](https://github.com/x64dbg/x64dbg/wiki/Compiling-the-whole-project).

### Use the CLI

```
x64dbg-cli.exe --selftest
x64dbg-cli.exe --json --userdir <empty dir>
x64dbg-cli.exe --interactive target.exe args
x64dbg-cli.exe --exec "init \"C:\path\target.exe\"" --exec "bp kernel32.Sleep" --exec "run" --exec "!regs --groups gpr"
```

The last line is the one-shot form: it runs the commands in order, then exits. The target can stop at the system and entry breakpoints first, so more `run` items may be needed (the example is adapted from [docs/cli/agent-guide.md](docs/cli/agent-guide.md)).

In `--json` mode the CLI prints a `hello` line, then reads one JSON request per line and writes one JSON response per line:

```json
{"id":7,"cmd":"run","timeout_ms":10000,"on_timeout":"keep"}
{"id":8,"op":"eval","args":{"expr":"rsp"}}
```

`cmd` is a native x64dbg command line, `op` is a structured view operation. Run `x64dbg-cli.exe --help` for all options. The full protocol is in [docs/cli/README.md](docs/cli/README.md).

### What is different from upstream

The GUI and the debugger core are unchanged, except for one small tweak in the core's logging thread. Everything else is added. The full list with the date is in [Modifications](#modifications).

New directories: `src\cli` (the CLI, JSON schemas and test scripts), `src\tests\cli_target` (a small test program for the CLI) and `docs\cli` (CLI documentation). The CLI was developed with the help of AI tools. Their working notes, logs and test evidence are kept in a local `.agents` directory, which `.gitignore` excludes, so it is not in this repository.

## Screenshots

_These screenshots show the upstream x64dbg GUI, which this fork does not change._

![main interface (light)](.github/screenshots/cpu-light.png)

![main interface (dark)](.github/screenshots/cpu-dark.png)

| ![graph](.github/screenshots/graph-light.png) | ![memory map](.github/screenshots/memory-map-light.png) |
| :--: | :--: |

## Installation & Usage

This section is upstream's text. The downloads it links to are the official upstream x64dbg snapshots. They are not built from this fork and do not contain `x64dbg-cli.exe`. To get the CLI, build this repository (see [Build the CLI](#build-the-cli)).

1. Download an upstream snapshot from [GitHub (upstream releases)](https://github.com/x64dbg/x64dbg/releases) or [SourceForge (upstream snapshots)](https://sourceforge.net/projects/x64dbg/files/snapshots) and extract it in a location your user has write access to.
2. _Optionally_ use `x96dbg.exe` to register a shell extension and add shortcuts to your desktop.
3. You can now run `x32\x32dbg.exe` if you want to debug a 32-bit executable or `x64\x64dbg.exe` to debug a 64-bit executable! If you are unsure you can always run `x96dbg.exe` and choose your architecture there.

You can also [compile](https://github.com/x64dbg/x64dbg/wiki/Compiling-the-whole-project) x64dbg yourself with a few easy steps!

## Sponsors

_These are sponsors of the upstream x64dbg project. They do not sponsor, endorse or have any relation to this fork._

<div align="center" markdown="1">

  <a href="https://sponsors.x64dbg.com/warp" target="_blank">
    <img alt="Warp sponsorship" width="400" src="https://raw.githubusercontent.com/warpdotdev/brand-assets/main/Github/Sponsor/Warp-Github-LG-02.png">
  </a>

  [**Warp, built for coding with multiple AI agents**](https://sponsors.x64dbg.com/warp)

<br>

[![](.github/sponsors/telekom.svg)](https://sponsors.x64dbg.com/telekom)

</div>

## Contributing

_This section is upstream's text and applies to the upstream x64dbg project. For this fork, see [Contributing to this fork](#contributing-to-this-fork)._

This is a community effort and we accept pull requests! See the [CONTRIBUTING](.github/CONTRIBUTING.md) document for more information. If you have any questions you can always [contact us](https://x64dbg.com/#contact) or open an [issue](https://github.com/x64dbg/x64dbg/issues). You can take a look at the [good first issues](https://easy.x64dbg.com/) to get started.

## Contributing to this fork

- Issues and pull requests about the CLI, its documentation or any other change made in this fork belong in this repository (<https://github.com/cicistudio-stack/x64dbg-cli/issues>).
- Contributions are accepted under the same license as the rest of the project (GNU GPL v3, see [License and copyright](#license-and-copyright)). By submitting a contribution you confirm that you have the right to submit it under that license.
- If a bug also happens in an official upstream snapshot, report it upstream. Do not report bugs of the CLI upstream.
- To sync with upstream:

```
git remote add upstream https://github.com/x64dbg/x64dbg.git
git fetch upstream
git merge upstream/development
```

After a merge, keep `LICENSE` and all upstream notices unchanged and update the [Modifications](#modifications) list.

## Credits

_The credits, developer list and thanks below are upstream's. They credit the authors of the original work._

- Debugger core by [TitanEngine Community Edition](https://github.com/x64dbg/TitanEngine)
- Disassembly powered by [Zydis](https://zydis.re)
- Assembly powered by [XEDParse](https://github.com/x64dbg/XEDParse) and [asmjit](https://github.com/asmjit)
- Import reconstruction powered by [Scylla](https://github.com/NtQuery/Scylla)
- JSON powered by [Jansson](https://www.digip.org/jansson)
- Database compression powered by [lz4](https://bitbucket.org/mrexodia/lz4)
- Bug icon by [VisualPharm](https://www.visualpharm.com)
- Interface icons by [Fugue](https://p.yusukekamiyamane.com)
- Website by [tr4ceflow](https://tr4ceflow.com)

## Developers

- [mrexodia](https://mrexodia.github.io)
- Sigma
- [tr4ceflow](https://blog.tr4ceflow.com)
- [Dreg](https://www.fr33project.org)
- [Nukem](https://github.com/Nukem9)
- [Herz3h](https://github.com/Herz3h)
- [torusrxxx](https://github.com/torusrxxx)

## Code contributions

You can find an exhaustive list of GitHub contributors [here](https://github.com/x64dbg/x64dbg/graphs/contributors).

## Special Thanks

- Sigma for developing the initial GUI
- All the donators!
- Everybody adding issues!
- People I forgot to add to this list
- [Writers of the blog](https://x64dbg.com/blog/2016/07/09/Looking-for-writers.html)!
- [EXETools community](https://forum.exetools.com)
- [Tuts4You community](https://forum.tuts4you.com)
- [ReSharper](https://www.jetbrains.com/resharper)
- [Coverity](https://www.coverity.com)
- acidflash
- cyberbob
- cypher
- Teddy Rogers
- TEAM DVT
- DMichael
- Artic
- ahmadmansoor
- \_pusher\_
- firelegend
- [kao](https://lifeinhex.com)
- sstrato
- [kobalicek](https://github.com/kobalicek)
- [athre0z](https://github.com/athre0z)
- [ZehMatt](https://github.com/ZehMatt)
- [mrfearless](https://twitter.com/fearless0)
- [JustMagic](https://github.com/JustasMasiulis)

Without the help of many people and other open-source projects, it would not have been possible to make x64dbg what it is today, thank you!

## License and copyright

**License.** This fork is distributed under the same license as x64dbg: the GNU General Public License, version 3 (29 June 2007), in the form found in the [LICENSE](LICENSE) file. That file is the x64dbg project's modified copy of the GPL v3 (its header says "THIS DOCUMENT HAS BEEN MODIFIED"). It adds a section "2. Treatment of plugins", which allows closed-source, non-standalone plugins that use x64dbg's plugin interface, and the sections after it are numbered one higher than in the standard GPL v3 text. This fork keeps that file unchanged. On 2026-10-28 its SHA-256 matched upstream's `development` branch (`1791B618E0AAB8312274D6D229E692A680CC633676CD7F87E189F79097951F92`).

**Version.** The LICENSE file says "version 3". The words "or any later version" appear only in the license's template for new programs, not as a grant for x64dbg. The source files carry no license headers, so this README does not offer "or any later version" either.

**Copyright.**

- The copyright in the original x64dbg code stays with the original authors and contributors: the x64dbg team and the people listed in [Developers](#developers), [Special Thanks](#special-thanks) and the [contributors page](https://github.com/x64dbg/x64dbg/graphs/contributors). Their copyright notices and the LICENSE file are retained.
- The modifications and new files of this fork (listed in [Modifications](#modifications)) are copyright (C) 2026 cicistudio-stack and the contributors of this fork. They are released under the same license, GNU GPL v3, because a work based on a GPL program must be licensed as a whole under the GPL.
- Following upstream's convention, source files have no per-file license header. The LICENSE file applies to all of them.

**What the license asks of you, in plain words.** Section numbers refer to the LICENSE file in this repository.

1. Keep the LICENSE file and all copyright and license notices (sections 5 and 6).
2. If you modify the code, mark clearly that you modified it and give the date (section 6a), and state that it is released under this license (6b). The whole work stays under this license (6c).
3. If you give binaries to others, you must also provide the Corresponding Source (this repository, in the state that matches the binaries) or follow another option of section 7. For binaries that you publish for download, the simplest way is to offer the matching source at the same place (section 7d). The recipients get the same rights under the same license (section 11).
4. Do not add further restrictions to the rights the license gives (sections 8 and 11).
5. There is no warranty (sections 16 and 17 of the LICENSE file, summarized in [Disclaimer](#disclaimer)).
6. Binary packages made from this repository can contain third-party files with their own terms, for example the Qt libraries and Microsoft runtime DLLs. Check [Third-party components](#third-party-components) before you redistribute them.

This is not legal advice. If you need certainty, for example for commercial use or redistribution, read the LICENSE file and ask a lawyer.

## Modifications

Notice under section 6a of the license. These are the changes that this fork made to the upstream x64dbg code, as of 2026-10-28. This fork started from upstream commit `79d57163d07432d24f0bff00298bfd2acd98f341`; the git history shows the exact dates, and you can compare with upstream, for example with `git diff 79d5716 HEAD` or `git diff upstream/development`.

Changed upstream files (from `git diff --stat`):

| File | Change |
|---|---|
| `cmake.toml` | adds the `cli` build target (`x64dbg-cli` / `x32dbg-cli` output names); +33 lines |
| `CMakeLists.txt` | the matching generated `cli` target; +106 lines |
| `src/dbg/console.cpp` | the two log forwarding tasks use a minimum sleep of 5 ms instead of the default 100 ms when the core runs headless (`BridgeIsHeadless()`); the GUI keeps the default; 2 lines |
| `src/tests/CMakeLists.txt` | registers the `cli_target` test program (also as an administrator variant); +7 lines |
| `docs/conf.py` | excludes `cli/*` from the Sphinx documentation build; 1 line |
| `.gitignore` | ignores the local `.agents/` directory; 1 line |
| `README.md`, `README_zh.md` | fork notice and the sections of this document |

New files and directories (not in upstream):

- `src/cli/`: the CLI (C++ sources, JSON schemas, Python test and generator scripts)
- `src/tests/cli_target/`: a test program for the CLI
- `docs/cli/`: CLI documentation

Not modifications: `src/dbg/btparser`, `src/third_party/TitanEngine`, `src/third_party/GleeBug` and `deps` are upstream's git submodules (see below).

## Third-party components

Third-party components keep their own licenses. This table lists what can be confirmed from files in this repository.

| Component | Where | License | Evidence |
|---|---|---|---|
| TitanEngine (debugger core) | `src/third_party/TitanEngine` | GNU LGPL v3 | `LICENSE` |
| diStorm (inside TitanEngine) | `src/third_party/TitanEngine/distorm` | BSD-style, copyright Gil Dabah | `COPYING` |
| GleeBug | `src/third_party/GleeBug` | MIT | `LICENSE` |
| btparser | `src/dbg/btparser` | Mozilla Public License 2.0 | `LICENSE` |
| Jansson | `src/dbg/jansson` | MIT | header of `jansson.h` |
| lz4 | `src/dbg/lz4` | BSD 2-Clause | header of `lz4.h` |
| concurrentqueue | `src/dbg/concurrentqueue` | simplified BSD, also Boost | header comments |
| Zydis | `src/zydis_wrapper/Zydis` | MIT-style permission notice | header of `Zydis.h` |

[docs/licenses.md](docs/licenses.md) is upstream's list. It also names XEDParse (LGPL), asmjit and asmtk (zlib) and Qt 5 (LGPL; see Qt licensing for the exact terms). Those components are not present as source with a license file in this checkout, so they are not verified here. No license information could be found in this checkout for Scylla, the LLVM demangler (prebuilt libraries in `src/dbg/LLVMDemangle`) and the prebuilt Microsoft files in `deps` (such as `dbghelp.dll`, `msdia140.dll` and the Visual C++ runtime), which are under Microsoft's terms and not under the GPL. The icons (VisualPharm, Fugue) are credited in [Credits](#credits); check their terms before redistributing.

`src\dbg\btparser`, `src\third_party\TitanEngine`, `src\third_party\GleeBug` and `deps` are git submodules that point to `https://github.com/x64dbg/btparser`, `.../TitanEngine`, `.../GleeBug` and `.../deps` (see `.gitmodules`). They are fetched with `git submodule update --init --recursive`. When the license check above was made, `deps` had no license file in the checkout.

## Disclaimer

- This software is provided as is, without warranty of any kind (sections 16 and 17 of the [LICENSE](LICENSE) file).
- It is meant for lawful security research, debugging and reverse engineering of software that you own or are authorized to analyze. You are responsible for complying with applicable laws and with the licenses of the software you analyze.
- An AI tool that drives the debugger can run code and change memory in the target process. Use it only on trusted or authorized targets, and analyze untrusted binaries in an isolated environment such as a virtual machine.
- Nothing in this README is legal advice.

## Historical Donors

_These donations were made to the upstream x64dbg project, not to this fork._

Before fully transitioning to [GitHub Sponsors](https://github.com/sponsors/mrexodia), this project received donations through BountySource. The original donation terms included an optional website link for donors who requested one at the time of donation. Links marked below reflect those requests. BountySource has since been shut down, so these records are reconstructed by hand. If you donated during this period and your username/amount is missing or incorrect, please reach out.

|Username|Amount|Date||Username|Amount|Date|
|-|-|-|-|-|-|-|
|sghctoma|$50|2015-04-19||dfrunza|$20|2017-01-30|
|overflow|$50|2015-04-25||ham3di|$100|2017-02-01|
|jl2id|$15|2015-04-29||johnny5|$5|2017-02-19|
|cypherpunk|$50|2015-05-02||David-Reguera-Garcia-Dreg|$90|2017-02-26|
|Aciid|$50|2015-05-05||[Alexandro Sanchez Bach](https://phi.nz)|-|2017-03-02|
|PI32|$15|2015-05-09||(unknown)|$6|2017-03-11|
|darkvapeur|$8|2015-05-21||fred26|$50|2017-04-08|
|fearless|$5|2015-05-24||gatesbillou|$20|2017-04-15|
|0x90|$10|2015-05-31||David-Reguera-Garcia-Dreg|$10|2017-04-24|
|acidflash|$50|2015-06-03||Adir|$20|2017-05-03|
|VackerSimon|$10|2015-06-14||ferbeb|$10|2017-05-17|
|Artic|$10|2015-06-29||(unknown)|$16|2017-06-04|
|[crystalidea](https://www.crystalidea.com/uninstall-tool)|$24|2015-07-10||androsa|$20|2017-06-11|
|jl2id|$10|2015-08-13||robersor|$25|2017-07-05|
|[PELock](https://pelock.com)|$115|2015-08-26||DDSTrainers|$10|2017-07-15|
|[tslater2006](https://github.com/tslater2006)|$20|2015-09-04||blaquee|$20|2017-08-27|
|Exidous|$20|2015-09-04||SmilingWolf|$15|2017-09-26|
|lupier|$40|2015-09-08||Alexander H.|$150|2017-10-11|
|Stef|$10|2015-09-15||gatesbillou|$25|2017-10-14|
|[d3v1l401](https://d3vsite.org)|$5|2015-10-06||t4rmo|$5|2017-10-18|
|Artur|$20|2015-10-24||joelcornu|$5|2017-10-27|
|RoBa|$100|2015-11-18||Adir|$35|2017-11-02|
|mr.tuna7331|-|2015-12-15||(unknown)|$10|2017-11-11|
|lupier|$90|2016-01-12||xdeng|$10|2018-01-04|
|fvrmatteo|$10|2016-01-21||v-p-b|$50|2018-03-21|
|willi.neu9|$10|2016-01-30||EmptyBrain|$50|2018-03-30|
|rithien|$100|2016-02-19||[mentebinaria](https://www.mentebinaria.com.br/)|$19|2018-04-12|
|ey|$20|2016-02-26||Mauro Bollini|$50|2018-06-07|
|clockwork|$10|2016-03-06||gatesbillou|$15|2018-06-17|
|codespy|$5|2016-03-23||Kirbiflint|$3|2018-06-22|
|test|$100|2016-03-28||Chisato Rokumiya|$20|2018-09-20|
|RomanGol|$10|2016-03-28||pengchang|$100|2018-10-24|
|fearless|$10|2016-04-24||younsunmin|$5|2018-11-18|
|Jack|$5|2016-05-17||EmptyBrain|$50|2018-12-27|
|willi.neu9|$30|2016-05-26||Yim|$10|2019-01-13|
|gatesbillou|$20|2016-06-02||[OALabs](https://www.youtube.com/c/OALabs)|-|2019-01-27|
|AGI|$155|2016-06-16||Lixinist|$10|2019-04-15|
|lupier|$100|2016-06-24||bloodmc|$50|2019-04-29|
|0x90|$50|2016-07-19||(unknown)|$20|2019-05-24|
|tr4nc3|$15|2016-07-31||masacate|$10|2019-07-10|
|MikeGuidry|$2500|2016-07-31||User Manuals|$5|2020-01-20|
|Alexander H.|$150|2016-09-09||Jim Conyngham|$50|2020-03-23|
|darkvapeur|$10|2016-10-04||Danya|$5|2020-06-08|
|h907308901|$5|2016-10-06||RooT|$160|2020-07-22|
|Adir|$20|2016-10-24||jadakiss9018|$2|2020-09-11|
|NicoG|$100|2016-10-27||samsonpianofingers|$15|2020-09-14|
|Angie|$150|2016-11-03||tpericin|$1337|2020-10-09|
|hulucc|$20|2016-12-02||nikkej|$100|2020-10-22|
|napcode|$10|2016-12-05||kha1ifaa|$10|2021-01-04|
|TechLord|-|2016-12-26||rikaardhosein|$20|2021-09-08|
|ayylmao5|$5|2017-01-01||Lukas21|$50|2021-09-15|
|affelwafro|$10|2017-01-03||Flavio Nardiello|$30|2021-12-01|
|FS|$40|2017-01-15||stevemk14ebr|$1000|2021-12-03|
|EmptyBrain|$50|2017-01-27||[ethical.blue](https://ethical.blue)|$19|2022-05-14|

_To all our early supporters: thank you for believing in this project before it became what it is today!_
