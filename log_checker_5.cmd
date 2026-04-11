@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "PYTHON_EXE=%SCRIPT_DIR%..\.venv\Scripts\python.exe"
set "LOG_CHECKER=%SCRIPT_DIR%log_checker_5.py"

if exist "%PYTHON_EXE%" (
    "%PYTHON_EXE%" "%LOG_CHECKER%" %*
) else (
    py -3 "%LOG_CHECKER%" %*
)

endlocal