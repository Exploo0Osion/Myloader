# Mirage

一个 Windows x64 Shellcode Loader：融合 **SilentMoonwalk** 的 stack spoofing 与 **SysWhispers3** 的 indirect syscall，并结合 **Module Stomping** 思路（将 `xpsservices.dll` 映射后用 shellcode 覆写其可执行代码段并执行）。

## 特性

- Indirect Syscall：基于 SysWhispers3（klezVirus 方案）。
- Stack Spoofing：基于 SilentMoonwalk（klezVirus 方案）。
- Module Stomping：加载并映射 `C:\Windows\System32\xpsservices.dll`，定位其可执行 section，写入并执行 payload。
- `shtools/`：提供 shellcode 模板构建与 `.text` 提取脚本，便于把 C/ASM 形式的 payload 编译为纯字节数组。

## 构建

在 “x64 Native Tools Command Prompt for VS” 中：

- `build.bat`
- 清理：`build.bat clean`

或使用 PowerShell 包装：

- `powershell -ExecutionPolicy Bypass -File build.ps1`
- 清理：`powershell -ExecutionPolicy Bypass -File build.ps1 -Action clean`

产物：`bin\MyLoader.exe`

## Shellcode 工作流（shtools）

`xpsservices.dll` 的 `.text` 默认是 RX，项目通过 `NtProtectVirtualMemory` 临时改成 RW 写入；为了更方便生成“能直接落到代码段执行”的 payload，使用 `shtools/` 以模板方式构建并提取字节数组：

- `cd shtools`
- `build_shellcode.bat`（生成 `shellcode.exe`）
- `python extract.py`（打印 `unsigned char shellcode[] = { ... };`）
- 将输出替换到 `src/loader.c` 内的 `shellcode[]` 数组即可

依赖：Python + `pefile`（例如：`pip install pefile`）。

## 免责声明

仅用于学习与研究，请勿用于未授权的测试或非法用途。
