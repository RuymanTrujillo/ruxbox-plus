@echo off
setlocal
rem Unico punto de entrada; evita saltarse el control del paquete.
call "%~dp0..\INICIAR.cmd"
exit /b %errorlevel%
