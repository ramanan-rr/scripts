for /f %%a in (idrac.txt) do (
racadm -r %%a -u root -p D3ll3mc@mw@cscsg serveraction powerup

rem uncomment the below to power down the system
rem racadm -r %%a -u root -p D3ll3mc@mw@cscsg serveraction powerdown

rem uncomment the below to power cycle the system
rem racadm -r %%a -u root -p D3ll3mc@mw@cscsg serveraction powercycle

rem uncomment the below to hard reset the system
rem racadm -r %%a -u root -p D3ll3mc@mw@cscsg serveraction hardreset
)