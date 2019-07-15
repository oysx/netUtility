echo off
for /L %%I in (0,1,10) do (
	netstat -n | find "1%" | find /C "TIME_WAIT"
	timeout /t 1 /nobreak > nul
)
