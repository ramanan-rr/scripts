# Define the list of iDRACs IPs here
$idracIps = @(
              "48.64.0.161",
			  "48.64.0.162",
			  "48.64.0.163",
			  "48.64.0.164")
$idracUser = "root"
$idracPwd = "D3ll3mc@mw@cscsg"
$filePath = "\\dd9400a.sg.csc\R\ApexCloudPlatform\ACP4RHOS\4.16.16-03.02.01.00\NIM-03.02.01.00-28810655-redhat_ocp-4.16.16.iso"
$fileUser = "username@domain"
$filePwd = "password"

foreach ($idrac in $idracIps) {
	Write-Host "Processing $idrac"
	racadm -r $idrac -u $idracUser -p $idracPwd remoteimage -c -u $fileUser -p  $filePwd -l $filePath --nocertwarn
	racadm -r $idrac -u $idracUser -p $idracPwd set iDRAC.VirtualMedia.BootOnce 1 --nocertwarn
	racadm -r $idrac -u $idracUser -p $idracPwd set iDRAC.ServerBoot.FirstBootDevice VCD-DVD --nocertwarn
	racadm -r $idrac -u $idracUser -p $idracPwd serveraction powercycle --nocertwarn
}