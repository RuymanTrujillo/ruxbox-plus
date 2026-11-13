@echo off
setlocal DisableDelayedExpansion
rem Verificar el paquete completo antes de ejecutar el cliente local de parada.
call "%~dp0VERIFICAR.cmd"
if errorlevel 1 (
  echo No se puede validar el paquete. No se intentara detener ningun proceso.
  exit /b 1
)
"%~dp0tools\node\node-v24.22.1-win-x64\node.exe" "%~dp0manager\stop.mjs"
exit /b %errorlevel%
