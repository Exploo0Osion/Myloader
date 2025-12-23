@echo off
setlocal

rem ============================================================================
rem  MyLoader Dynamic Build (Smallest Size)
rem  Features:
rem    - Dynamic CRT (/MD): Uses system DLLs to keep EXE size ~20KB.
rem    - Intrinsics (/Oi): No imports for memset/memcpy.
rem    - SEH Support: Retains try/catch (Imports __C_specific_handler).
rem ============================================================================

if /i "%~1"=="clean" goto :clean

where cl >nul 2>nul
if errorlevel 1 (
  echo [!] cl.exe not found. Run from "x64 Native Tools Command Prompt for VS".
  exit /b 1
)

if not exist bin mkdir bin
if not exist obj mkdir obj

rem ----------------------------------------------------------------------------
rem 1. Assemble ASM
rem ----------------------------------------------------------------------------
echo [*] Assembling src\asm\gate.asm...
ml64 /nologo /c /Fo obj\gate.obj src\asm\gate.asm
if errorlevel 1 exit /b 1

rem ----------------------------------------------------------------------------
rem 2. Compile C Sources
rem ----------------------------------------------------------------------------
rem /MD   : Dynamic CRT (Smallest EXE size, depends on system DLLs)
rem /O1   : Minimize Size
rem /Ob2  : Inline expansion (Speed & Obfuscation)
rem /Oi   : Enable Intrinsic Functions (Critical for hiding memset imports)
rem /Os   : Favor Small Code
rem /GS-  : No Security Cookies (Clean stack, fewer imports)
rem /Gy   : Function-Level Linking (Allows Linker to strip unused code)
rem /GL   : Whole Program Optimization
rem /Gw   : Optimize Global Data
rem ----------------------------------------------------------------------------
echo [*] Compiling C sources...

cl /nologo /MD /O1 /Ob2 /Oi /Os /GS- /Gy /GL /Gw /I include /c /Foobj\ ^
src\utils\gadgets.c ^
src\utils\pe_utils.c ^
src\globals.c ^
src\engine.c ^
src\loader.c ^
src\main.c ^
/utf-8

if errorlevel 1 exit /b 1

rem ----------------------------------------------------------------------------
rem 3. Linking
rem ----------------------------------------------------------------------------
rem /OPT:REF  : Strips unused functions
rem /OPT:ICF  : Merges identical code
rem Note: We do NOT use /NODEFAULTLIB here because we need the dynamic CRT 
rem for SEH (__try/__except) and startup code.
rem ----------------------------------------------------------------------------
echo [*] Linking bin\MyLoader.exe...

link /nologo /SUBSYSTEM:CONSOLE ^
/LTCG /OPT:REF /OPT:ICF ^
/MERGE:.rdata=.text ^
/MERGE:.data=.text ^
/SECTION:.text,ERW ^
/OUT:bin\MyLoader.exe ^
obj\*.obj

if errorlevel 1 exit /b 1

echo.
echo [+] Build Success!
echo [+] Output: bin\MyLoader.exe
echo.
exit /b 0

:clean
if exist bin rmdir /s /q bin
if exist obj rmdir /s /q obj
exit /b 0