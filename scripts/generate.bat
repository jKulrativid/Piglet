@echo off

@REM Please set VITIS_HLS_PATH to env vars. Ex."C:\Programs\Xilinx\Vitis_HLS\2023.2\bin"
if not defined VITIS_HLS_PATH (
    echo !! ERROR !! 
    echo environment variable 'VITIS_HLS_PATH' is not set. 
    echo please set it with path to vitis. Ex. C:\Programs\Xilinx\Vitis_HLS\2023.2\bin
    echo -----------------------------------------------------------------------------
    goto ERR
)

set PATH=%VITIS_HLS_PATH%;%PATH%;%VITIS_HLS_PATH%..\msys64\usr\bin;%VITIS_HLS_PATH%..\msys64\mingw64\bin

set AUTOESL_HOME=%VITIS_HLS_PATH%..
set VIVADO_HLS_HOME=%VITIS_HLS_PATH%..

echo ===============================
echo == Vitis HLS Command Prompt 
echo == Available commands:
echo == vitis_hls,apcc,gcc,g++,make
echo ===============================


set RDI_OS_ARCH=32
if [%PROCESSOR_ARCHITECTURE%] == [x86] (
  if defined PROCESSOR_ARCHITEW6432 (
    set RDI_OS_ARCH=64
  )
) else (
  if defined PROCESSOR_ARCHITECTURE (
    set RDI_OS_ARCH=64
  )
)

if not "%RDI_OS_ARCH%" == "64" goto _NotX64
set COMSPEC=%WINDIR%\SysWOW64\cmd.exe
goto EOF

:_NotX64
set COMSPEC=%WINDIR%\System32\cmd.exe
rem %COMSPEC% /c %0 %1 %2 %3 %4 %5 %6 %7 %8 %9 
 
:EOF
cmd /c ^
vitis_hls -run tcl run-hls-packet-manager.tcl ^
& echo "======= Generate Completed ======="
set /p wantOpenIDE=Want to open Vitis HLS (y/N)?:
if /i "%wantOpenIDE%"=="y" (
    echo Opening Vitis HLS...
    vitis_hls
) 


:ERR
%COMSPEC%
