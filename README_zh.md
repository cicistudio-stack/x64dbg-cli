# x64dbg-cli

[English](README.md) | 简体中文

> **本项目是一个分支（fork），不是官方的 x64dbg。** x64dbg-cli 基于 [x64dbg](https://github.com/x64dbg/x64dbg)，新增了命令行接口（`x64dbg-cli.exe`），方便 AI 工具和脚本驱动调试器。本分支由其所有者独立维护，与 x64dbg 的作者和团队没有隶属关系，也未获得他们的认可或支持。原始代码的版权仍归原作者所有，并按原许可证（GNU GPL v3，见[许可证与版权](#许可证与版权)）使用。使用本分支时遇到的问题，请在本仓库的 issue 中反馈，不要到 x64dbg 的 Discord、Slack、Gitter、Matrix、IRC 或 issue 页面提问。详情见[关于本分支](#关于本分支)。本文不构成法律意见。

<img width="100" src="./src/bug_black.png"/>

一个开源的Windows二进制调试器，旨在进行恶意软件分析和你没有源代码的可执行文件的逆向工程。有许多可用的功能和一个全面的[插件系统](https://plugins.x64dbg.com) 来添加你自己的功能。你可以在[博客](https://x64dbg.com/blog)上找到更多信息!

## 用 AI 驱动调试器

本分支的主要用途：让 AI 智能体像你在图形界面里一样调试 Windows 程序。它可以设置断点、运行程序、读取寄存器、实时反汇编、堆栈、调用栈和内存，单步执行、计算表达式、修改内存，并把地址和数值作为依据汇报出来。智能体通过 `x64dbg-cli.exe` 与调试器交互（先构建：[构建 CLI](#构建-cli)）。只支持 64 位目标程序。

### 接入 AI 的几种方式

| 你的情况 | 做法 |
|---|---|
| **能执行 shell 命令的 AI 工具或编程助手** | 告诉它 `x64dbg-cli.exe` 的路径，让它使用一次性形式（`--exec`，见[使用 CLI](#使用-cli)）。每次调用都会新开一个调试会话，所以要把整个流程（加载程序、下断点、运行、查看状态）放进同一次调用。适合“运行到这个断点，告诉我当时的状态”这类任务。 |
| **你自己的智能体、脚本，或支持工具调用的智能体框架** | 把 `x64dbg-cli.exe --json --userdir <新建的空目录>` 作为子进程启动。向它的 stdin 每行写一个 JSON 请求，从 stdout 每行读一个 JSON 响应。会话在多次请求之间保持不变，所以智能体可以单步、查看、再决定下一步。把 [docs/cli/ai-system-prompt.md](docs/cli/ai-system-prompt.md) 作为系统提示词。[docs/cli/examples/client.py](docs/cli/examples/client.py) 是一个可以直接参考的小型客户端（只用标准库）。 |
| **基于 MCP 的客户端** | 本分支不带 MCP 服务端。[docs/cli/agent-guide.md](docs/cli/agent-guide.md) 说明了如何把协议包装成 MCP 工具（一个通用命令工具，或每个操作一个工具），并附有简短示例。 |

### 快速开始

1. 构建 CLI（[构建 CLI](#构建-cli)），得到 `bin\x64\x64dbg-cli.exe`。
2. 自检：`x64dbg-cli.exe --selftest`。
3. 给 AI 配置指令：把 [docs/cli/ai-system-prompt.md](docs/cli/ai-system-prompt.md) 的正文作为系统提示词，去掉文件开头的 HTML 注释（那段注释是写给人看的中文说明）。提示词涵盖协议、全部 80 个结构化操作、数字和地址规则、常见调试流程、安全规则和已知限制，约 9k token。
4. 让你的程序把 CLI 作为子进程启动：`x64dbg-cli.exe --json --userdir <每个会话都新建一个空目录>`，并把 AI 输出的 JSON 行转给它。想先不写代码看看效果，可以运行示例客户端：`python docs\cli\examples\client.py bin\x64\x64dbg-cli.exe <target.exe>`。
5. 用自然语言向 AI 提问，例如：
   - “调试 `C:\samples\app.exe`，在 `kernel32.CreateFileW` 下断点，告诉我它打开的文件名，并给出调用栈。”
   - “运行到程序崩溃为止，给出寄存器、出错的指令，以及 `rsp` 附近的 16 个栈项。”
   - “找到字符串 `license` 在哪里被引用，并解释那附近的代码。”
   - “单步跟踪 `rip` 处的函数，说明它做了什么，并显示 `rcx` 指向的内存。”

### AI 可以使用的功能

图形界面能显示的内容，都可以通过命令获得。AI 用带类型的 JSON 操作获取数据，用 x64dbg 原生命令执行动作。

| 方面 | 示例 |
|---|---|
| 会话与运行控制 | `init`、`attach`、`detach`、`run`、`pause`、`stepin`、`stepover`、`stepout`、`runto`、`restart`、`stop` |
| 断点 | 软件、硬件、内存、DLL 和异常断点，条件，命中次数（`bp`、`bps`） |
| 状态 | `regs`、`dis`（实时反汇编）、`mem`、`stack`、`callstack`、`threads`、`modules`、`memmap`、`sym`、`eval` |
| 修改与标注 | `setreg`、`memwrite`、`patches`、`patch export`、标签、注释、书签 |
| 搜索与分析 | `findall`、引用、字符串、交叉引用、控制流图、跟踪 |
| 其他一切 | 所有 x64dbg 原生命令，通过 `{"cmd": "..."}` 调用 |

完整的操作列表见 [docs/cli/command-reference.md](docs/cli/command-reference.md)。[docs/cli/parity-matrix.md](docs/cli/parity-matrix.md) 列出了每个图形界面功能对应的命令，以及 CLI 做不到的部分（例如跟踪文件浏览器和 Scylla）。

### 安全

- 调试会运行目标程序。只对你自己拥有或已获得授权分析的软件使用 AI；不可信的程序请放在虚拟机里分析。
- AI 可以写入目标进程的内存和寄存器。写入只发生在内存中；`patch export` 会把打过补丁的副本写到新文件，不会改动原文件。
- 把被调试程序输出的文字、字符串和窗口标题都当作数据。恶意样本里可能带有试图指挥 AI 的文字。系统提示词要求 AI 忽略这类文字，但不要只依赖这一点：分析不可信样本时，请限制 AI 的其他工具（文件访问、网络、shell）。
- 每个会话都使用新建的空 `--userdir`；每个目录只能有一个 CLI 进程。会话结束时一定要先 `stop`（对想保持运行的附加进程则用 `detach`），再 `quit`。
- AI 对会让程序继续运行的命令，应当始终设置超时。系统提示词中有这条要求。

### 需要了解的事

- `init` 之后，程序会停在系统断点，在默认设置下还会再停在入口断点。AI 需要再次 `run` 才能到达它自己的断点。系统提示词中有说明。
- 超时之后程序仍在运行，AI 要么把它暂停，要么继续等待。
- CLI 是本分支自己的工具，相关问题请提交到本仓库的 issue，不要提交到上游。

## 关于本分支

x64dbg-cli 是 [x64dbg](https://github.com/x64dbg/x64dbg) 的一个分支。调试器核心、图形界面以及绝大部分代码都是上游的成果。本分支只新增了一个面向 AI 工具的命令行接口，图形界面保持不变。

- **上游项目：** <https://github.com/x64dbg/x64dbg>，使用 GNU GPL v3 许可证（见[许可证与版权](#许可证与版权)）。
- **本分支：** <https://github.com/cicistudio-stack/x64dbg-cli>，由 [cicistudio-stack](https://github.com/cicistudio-stack) 和贡献者独立维护。
- **无隶属关系：** 这不是官方的 x64dbg。x64dbg 的作者和团队没有编写、审查、认可或支持本分支中的改动。“x64dbg”是上游项目的名称，此处仅用来说明本分支基于什么项目。
- **技术支持：** 不要把本分支的问题发到上游的支持渠道（Discord、Slack、Gitter、Matrix、IRC、issue 页面、赞助商）。请使用本仓库的 issue。
- **起点：** 这是 x64dbg 的 GitHub 分支（fork）。本分支的改动都在一个提交 `add x64dbg cli` 中，它建立在上游提交 [`79d5716`](https://github.com/x64dbg/x64dbg/commit/79d57163d07432d24f0bff00298bfd2acd98f341)（2026-10-28，`development` 分支）之上。上游的完整历史也在本仓库中。

### 本分支新增的内容

`x64dbg-cli.exe` 是一个控制台程序。它加载 x64dbg 的核心（`x64dbg.dll`、`x64bridge.dll`）而不是 Qt 图形界面，并通过标准输入/输出提供调试器功能，供 AI 工具、智能体和脚本使用。它不依赖 Qt 或图形界面。

- JSON Lines 协议（`--json`）和纯文本 REPL，以及一次性执行模式（`--exec`、`--script`）。
- 结构化的视图操作（op），以 JSON 返回图形界面各窗格的数据：寄存器、实时反汇编、内存、栈和调用栈、断点、线程、模块、内存布局、符号、句柄等。[docs/cli/README.md](docs/cli/README.md) 中记录了 80 个 op。
- 原样透传所有 x64dbg 原生命令（与图形界面命令栏相同的命令；据 [docs/cli/native-commands.md](docs/cli/native-commands.md) 共 348 条）。
- 图形界面与 CLI 的对照表，逐项列出每个窗格和操作对应的命令，以及已知的缺口（例如 trace 浏览器）：[docs/cli/parity-matrix.md](docs/cli/parity-matrix.md)。

文档位于 [docs/cli/](docs/cli/README.md)：

| 文件 | 内容 |
|---|---|
| [README.md](docs/cli/README.md) | 用法、协议、命令概览 |
| [agent-guide.md](docs/cli/agent-guide.md) | 面向 AI 智能体的指南，以及如何把 CLI 封装成 MCP 工具 |
| [ai-system-prompt.md](docs/cli/ai-system-prompt.md) | 使用该 CLI 的 AI 工具的系统提示词 |
| [command-reference.md](docs/cli/command-reference.md) | 每个 op 的参数和结果结构 |
| [parity-matrix.md](docs/cli/parity-matrix.md) | 图形界面与 CLI 的对照表 |

### 构建 CLI

目前只有 64 位版本有文档并经过测试。构建环境是 Visual Studio 2026 Community（MSVC 14.51）、CMake 和 Visual Studio 自带的 Ninja。另外需要 Git。

1. 连同子项目一起克隆（它们是上游的 git 子模块）：

```
git clone --recursive https://github.com/cicistudio-stack/x64dbg-cli.git
cd x64dbg-cli
```

   如果已经克隆过，请运行 `git submodule update --init --recursive`。

2. 打开“适用于 VS 的 x64 本机工具命令提示符”（它会运行 `vcvars64.bat`），在仓库根目录执行：

```
cmake -B build64 -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_UNITY_BUILD=ON -DCMAKE_UNITY_BUILD_BATCH_SIZE=6 -DX64DBG_RELEASE=OFF
cmake --build build64
```

生成结果是 `bin\x64\x64dbg-cli.exe`，与图形界面及其所需的 DLL 放在同一目录。构建 CLI 时也会构建 Qt 图形界面。第一次配置时，上游的构建脚本会从 x64dbg 的 `deps` 发布页下载预编译的 Qt 5 包，体积较大。另见上游的[编译指南](https://github.com/x64dbg/x64dbg/wiki/Compiling-the-whole-project)。

### 使用 CLI

```
x64dbg-cli.exe --selftest
x64dbg-cli.exe --json --userdir <empty dir>
x64dbg-cli.exe --interactive target.exe args
x64dbg-cli.exe --exec "init \"C:\path\target.exe\"" --exec "bp kernel32.Sleep" --exec "run" --exec "!regs --groups gpr"
```

最后一行是一次性执行模式：按顺序执行这些命令，然后退出。目标程序可能会先停在系统断点和入口断点，所以可能需要更多的 `run`（该示例改编自 [docs/cli/agent-guide.md](docs/cli/agent-guide.md)）。

在 `--json` 模式下，CLI 先输出一行 `hello`，然后每行读取一个 JSON 请求，并为每个请求输出一行 JSON 响应：

```json
{"id":7,"cmd":"run","timeout_ms":10000,"on_timeout":"keep"}
{"id":8,"op":"eval","args":{"expr":"rsp"}}
```

`cmd` 是一条 x64dbg 原生命令，`op` 是结构化的视图操作。运行 `x64dbg-cli.exe --help` 可查看全部选项。完整协议见 [docs/cli/README.md](docs/cli/README.md)。

### 与上游的差异

图形界面和调试器核心保持不变，只有核心日志线程中的一处小改动。其余都是新增内容。完整清单和日期见[修改说明](#修改说明)。

新增目录：`src\cli`（CLI、JSON 结构定义和测试脚本）、`src\tests\cli_target`（CLI 用的小型测试程序）和 `docs\cli`（CLI 文档）。CLI 是在 AI 工具的协助下开发的，它们的工作笔记、日志和测试记录保存在本地的 `.agents` 目录中。`.gitignore` 已排除该目录，所以它不在本仓库里。

## 屏幕截图

_这些截图展示的是上游 x64dbg 的图形界面，本分支没有改动它。_

<!-- TODO: recreate Chinese screenshots -->

![main interface (light)](.github/screenshots/cpu-light.png)

![main interface (dark)](.github/screenshots/cpu-dark.png)

| ![graph](.github/screenshots/graph-light.png) | ![memory map](.github/screenshots/memory-map-light.png) |
| :--: | :--: |

## 安装与使用

本节是上游的内容。其中链接的下载是上游 x64dbg 的官方快照，不是由本分支构建的，也不包含 `x64dbg-cli.exe`。要获得 CLI，请自行构建本仓库（见[构建 CLI](#构建-cli)）。

1. 从 [GitHub（上游发布页）](https://github.com/x64dbg/x64dbg/releases)或 [SourceForge（上游快照）](https://sourceforge.net/projects/x64dbg/files/snapshots)下载上游快照，并将其解压缩到您的用户具有写权限的位置。
2. _可选择_ 使用 `x96dbg.exe` 来注册一个shell扩展，并在桌面上添加快捷方式。
3. 如果你想调试一个32位的可执行文件，你现在可以运行 `x32\x32dbg.exe` 或者 `x64\x64dbg.exe`来调试一个64位的可执行文件。如果你不确定，你可以随时运行 `x96dbg.exe` 并在那里选择你的架构。

你也可以通过几个简单的步骤[自己编译](https://github.com/x64dbg/x64dbg/wiki/Compiling-the-whole-project) x64dbg!

## 赞助商

_以下是上游 x64dbg 项目的赞助商。他们与本分支没有赞助、认可或其他关系。_

<div align="center" markdown="1">

  <a href="https://sponsors.x64dbg.com/warp" target="_blank">
    <img alt="Warp sponsorship" width="400" src="https://raw.githubusercontent.com/warpdotdev/brand-assets/main/Github/Sponsor/Warp-Github-LG-02.png">
  </a>

  [**Warp, built for coding with multiple AI agents**](https://sponsors.x64dbg.com/warp)

<br>

[![](.github/sponsors/telekom.svg)](https://sponsors.x64dbg.com/telekom)

</div>

## 贡献

_本节是上游的内容，适用于上游 x64dbg 项目。本分支的贡献方式见[为本分支贡献](#为本分支贡献)。_

这是一个社区的努力，我们接受拉取请求! 更多信息请参见 [CONTRIBUTING](.github/CONTRIBUTING.md) 文档。如果你有任何问题，你可以随时[联系我们](https://x64dbg.com/#contact)或提交一个[问题](https://github.com/x64dbg/x64dbg/issues). 你可以看一下[容易解决的问题](https://easy.x64dbg.com/)以开始贡献。

## 为本分支贡献

- 与 CLI、CLI 文档或本分支其他改动有关的 issue 和拉取请求，请提交到本仓库（<https://github.com/cicistudio-stack/x64dbg-cli/issues>）。
- 贡献按与项目其余部分相同的许可证（GNU GPL v3，见[许可证与版权](#许可证与版权)）接受。提交贡献即表示你确认自己有权按该许可证提交。
- 如果某个 bug 在上游官方快照中同样存在，请向上游报告。不要把 CLI 的 bug 报告给上游。
- 与上游同步：

```
git remote add upstream https://github.com/x64dbg/x64dbg.git
git fetch upstream
git merge upstream/development
```

合并之后，请保持 `LICENSE` 和所有上游声明不变，并更新[修改说明](#修改说明)中的清单。

## 制作人员

_以下制作人员、开发人员和特别感谢名单属于上游，用于致谢原始作品的作者。_

- 调试器核心由[TitanEngine社区版](https://github.com/x64dbg/TitanEngine)提供技术支持
- 反汇编引擎由 [Zydis](https://zydis.re)提供技术支持
- 汇编由 [XEDParse](https://github.com/x64dbg/XEDParse) 和 [asmjit](https://github.com/asmjit)提供技术支持
- 导入重建由 [Scylla](https://github.com/NtQuery/Scylla)提供技术支持
- JSON由 [Jansson](https://www.digip.org/jansson)提供技术支持
- 数据库优化由 [lz4](https://bitbucket.org/mrexodia/lz4)提供技术支持
- Bug 图标由 [VisualPharm](https://www.visualpharm.com)设计
- 界面图标由[Fugue](https://p.yusukekamiyamane.com)设计
- 网站由[tr4ceflow](https://tr4ceflow.com)负责

## 开发人员

- [mrexodia](https://mrexodia.github.io)
- Sigma
- [tr4ceflow](https://blog.tr4ceflow.com)
- [Dreg](https://www.fr33project.org)
- [Nukem](https://github.com/Nukem9)
- [Herz3h](https://github.com/Herz3h)
- [torusrxxx](https://github.com/torusrxxx)

## 代码贡献

你可以在[这里](https://github.com/x64dbg/x64dbg/graphs/contributors)找到一份详尽的GitHub贡献者名单.

## 特别感谢

- Sigma开发了初始图形用户界面
- 所有的捐赠者!
- 每一个提交问题的人!
- 我忘记添加到这个名单的人
- [博客文章作者](https://x64dbg.com/blog/2016/07/09/Looking-for-writers.html)
- [EXETools 社区](https://forum.exetools.com)
- [Tuts4You 社区](https://forum.tuts4you.com)
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

如果没有许多人和其他开源项目的帮助，就不可能使x64dbg成为今天的样子，谢谢你们!

## 许可证与版权

**许可证。** 本分支采用与 x64dbg 相同的许可证：GNU 通用公共许可证第 3 版（GNU General Public License, version 3，2007 年 6 月 29 日），以 [LICENSE](LICENSE) 文件中的文本为准。该文件是 x64dbg 项目修改过的 GPL v3 文本（文件开头写有 “THIS DOCUMENT HAS BEEN MODIFIED”）。它增加了一节 “2. Treatment of plugins”，允许使用 x64dbg 插件接口的、不能独立运行的闭源插件；该节之后的各节编号比标准 GPL v3 文本大 1。本分支保持该文件不变。2026-10-28 核对时，它的 SHA-256 与上游 `development` 分支的 LICENSE 一致（`1791B618E0AAB8312274D6D229E692A680CC633676CD7F87E189F79097951F92`）。

**版本。** LICENSE 文件写的是 “version 3”。“or any later version”（或任何更新版本）这几个字只出现在许可证中给新程序使用的声明模板里，并不是对 x64dbg 的授权。源文件没有许可证头，所以本 README 也不提供“或更新版本”。

**版权。**

- 原始 x64dbg 代码的版权仍归原作者和贡献者所有，包括 x64dbg 团队，以及[开发人员](#开发人员)、[特别感谢](#特别感谢)和[贡献者页面](https://github.com/x64dbg/x64dbg/graphs/contributors)中列出的人。他们的版权声明和 LICENSE 文件均予保留。
- 本分支的修改和新增文件（见[修改说明](#修改说明)）的版权归 cicistudio-stack 和本分支的贡献者所有（Copyright (C) 2026）。它们按同一许可证 GNU GPL v3 发布，因为基于 GPL 程序的作品必须整体按 GPL 授权。
- 沿用上游的惯例，源文件没有单独的许可证头，LICENSE 文件适用于所有这些文件。

**许可证对你的要求（通俗说明）。** 下面的条款编号指本仓库 LICENSE 文件中的编号。

1. 保留 LICENSE 文件以及所有版权和许可证声明（第 5、6 节）。
2. 如果你修改了代码，要明确标注你做了修改并写明日期（第 6a 节），并说明它按本许可证发布（6b）。整个作品都继续适用本许可证（6c）。
3. 如果你把二进制文件交给他人，必须同时提供对应源代码（本仓库中与二进制文件相匹配的版本），或采用第 7 节的其他方式。对于提供下载的二进制文件，最简单的做法是在同一地点提供相应的源代码（第 7d 节）。接收者在同一许可证下获得相同的权利（第 11 节）。
4. 不得对许可证所授予的权利附加其他限制（第 8、11 节）。
5. 不提供任何担保（LICENSE 文件第 16、17 节，摘要见[免责声明](#免责声明)）。
6. 由本仓库构建的二进制包里可能带有第三方文件，它们有各自的条款，例如 Qt 库和微软运行库 DLL。再分发前请先看[第三方组件](#第三方组件)。

本文不构成法律意见。如果需要确定的结论（例如商业使用或再分发），请阅读 LICENSE 文件并咨询律师。

## 修改说明

这是依据许可证第 6a 节给出的声明。以下是截至 2026-10-28 本分支对上游 x64dbg 代码所做的改动。本分支从上游提交 `79d57163d07432d24f0bff00298bfd2acd98f341` 开始；git 历史会显示确切日期，也可以与上游对比，例如运行 `git diff 79d5716 HEAD` 或 `git diff upstream/development`。

被修改的上游文件（来自 `git diff --stat`）：

| 文件 | 改动 |
|---|---|
| `cmake.toml` | 新增 `cli` 构建目标（输出名为 `x64dbg-cli` / `x32dbg-cli`）；增加 33 行 |
| `CMakeLists.txt` | 对应生成的 `cli` 目标；增加 106 行 |
| `src/dbg/console.cpp` | 核心以无界面（headless）方式运行时（`BridgeIsHeadless()`），两个日志转发任务的最小休眠时间从默认的 100 ms 改为 5 ms；图形界面仍使用默认值；改动 2 行 |
| `src/tests/CMakeLists.txt` | 注册 `cli_target` 测试程序（含管理员权限的变体）；增加 7 行 |
| `docs/conf.py` | 在 Sphinx 文档构建中排除 `cli/*`；改动 1 行 |
| `.gitignore` | 忽略本地的 `.agents/` 目录；增加 1 行 |
| `README.md`、`README_zh.md` | 分支声明以及本文档的各节 |

新增的文件和目录（上游没有）：

- `src/cli/`：CLI（C++ 源码、JSON 结构定义、Python 测试和生成脚本）
- `src/tests/cli_target/`：CLI 用的测试程序
- `docs/cli/`：CLI 文档

不属于修改的内容：`src/dbg/btparser`、`src/third_party/TitanEngine`、`src/third_party/GleeBug` 和 `deps` 是上游的 git 子模块（见下文）。

## 第三方组件

第三方组件保留各自的许可证。下表只列出能从本仓库文件中确认的内容。

| 组件 | 位置 | 许可证 | 依据 |
|---|---|---|---|
| TitanEngine（调试器核心） | `src/third_party/TitanEngine` | GNU LGPL v3 | `LICENSE` |
| diStorm（TitanEngine 内） | `src/third_party/TitanEngine/distorm` | BSD 风格，版权 Gil Dabah | `COPYING` |
| GleeBug | `src/third_party/GleeBug` | MIT | `LICENSE` |
| btparser | `src/dbg/btparser` | Mozilla Public License 2.0 | `LICENSE` |
| Jansson | `src/dbg/jansson` | MIT | `jansson.h` 文件头 |
| lz4 | `src/dbg/lz4` | BSD 2-Clause | `lz4.h` 文件头 |
| concurrentqueue | `src/dbg/concurrentqueue` | 简化 BSD，另有 Boost 许可 | 文件头注释 |
| Zydis | `src/zydis_wrapper/Zydis` | MIT 风格的许可声明 | `Zydis.h` 文件头 |

[docs/licenses.md](docs/licenses.md) 是上游给出的清单，其中还提到 XEDParse（LGPL）、asmjit 和 asmtk（zlib）以及 Qt 5（LGPL；具体条款请参见 Qt 的授权说明）。这些组件在本检出副本中没有带许可证文件的源码，所以这里没有核实。Scylla、LLVM 反修饰库（`src/dbg/LLVMDemangle` 中的预编译库）以及 `deps` 中预编译的微软文件（如 `dbghelp.dll`、`msdia140.dll` 和 Visual C++ 运行库）在本检出副本中找不到许可证信息；其中微软文件适用微软的条款，不属于 GPL。图标（VisualPharm、Fugue）见[制作人员](#制作人员)的致谢，再分发前请查阅它们的条款。

`src\dbg\btparser`、`src\third_party\TitanEngine`、`src\third_party\GleeBug` 和 `deps` 是指向 `https://github.com/x64dbg/btparser`、`.../TitanEngine`、`.../GleeBug` 和 `.../deps` 的 git 子模块（见 `.gitmodules`），用 `git submodule update --init --recursive` 获取。做上面的许可证核查时，`deps` 在检出副本中没有许可证文件。

## 免责声明

- 本软件按“现状”提供，不附带任何形式的担保（见 [LICENSE](LICENSE) 文件第 16、17 节）。
- 它用于合法的安全研究、调试，以及对你拥有或已获授权分析的软件进行逆向工程。你有责任遵守适用的法律以及被分析软件的许可条款。
- 驱动调试器的 AI 工具可以在目标进程中运行代码并修改内存。只对可信或已获授权的目标使用，分析不可信的二进制文件时请在虚拟机等隔离环境中进行。
- 本 README 中的任何内容都不构成法律意见。

## 历史捐赠者

_以下捐赠是捐给上游 x64dbg 项目的，不是捐给本分支的。_

在完全转向 [GitHub Sponsors](https://github.com/sponsors/mrexodia) 之前，该项目通过 BountySource 接收捐款。最初的捐赠条款允许捐赠者在捐赠时提供一个可选的网站链接，下表中带链接的条目就是按这些请求添加的。BountySource 已经关闭，所以这些记录是手工重建的。如果你在此期间捐过款，但你的用户名或金额缺失或有误，请联系上游。

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

_感谢所有早期的支持者：在这个项目成为今天的样子之前，你们就相信了它!_
