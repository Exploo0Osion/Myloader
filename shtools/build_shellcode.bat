@echo off

echo [*] Cleaning...
if exist *.obj del *.obj
if exist *.exe del *.exe

echo [*] Assembling Utils...
rem /c: 只编译不链接
ml64 /nologo /c utils.asm

echo [*] Compiling Shellcode...
cl /nologo /c /O1 /GS- /Tc shellcode.c

echo [*] Linking...
link /nologo /ENTRY:EntryPoint /NODEFAULTLIB /SUBSYSTEM:CONSOLE shellcode.obj utils.obj /OUT:shellcode.exe

echo [*] Build Done. shellcode.exe created.