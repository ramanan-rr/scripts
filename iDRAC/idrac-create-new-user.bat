for /f %%a in (idrac.txt) do (

rem Change root password if necessary
rem racadm -r %%a -u root -p calvin set idrac.Users.2.Password D3ll3mc@mw@cscsg

racadm -r %%a -u root -p D3ll3mc@mw@cscsg set idrac.users.3.username sanjeev
racadm -r %%a -u root -p D3ll3mc@mw@cscsg set idrac.users.3.password P@ssw0rd123!
rem set privilege to allow login, remote console and virtual media
racadm -r %%a -u root -p D3ll3mc@mw@cscsg set idrac.users.3.privilege 0x00000061
racadm -r %%a -u root -p D3ll3mc@mw@cscsg set idrac.users.3.enable 1
)