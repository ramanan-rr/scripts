for /f %%a in (idrac.txt) do (

rem Change root password if necessary
racadm -r %%a -u root -p ScaleIO123! set idrac.Users.2.Password D3ll3mc@mw@cscsg

rem racadm -r %%a -u root -p D3ll3mc@mw@cscsg set idrac.users.3.username sanjeev
rem racadm -r %%a -u root -p D3ll3mc@mw@cscsg set idrac.users.3.password P@ssw0rd123!
rem set privilege to allow login, remote console and virtual media
rem racadm -r %%a -u root -p D3ll3mc@mw@cscsg set idrac.users.3.privilege 0x00000061
rem racadm -r %%a -u root -p D3ll3mc@mw@cscsg set idrac.users.3.enable 1
)