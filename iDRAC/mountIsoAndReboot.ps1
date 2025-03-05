# Define the list of iDRACs IPs here
$idracIps = @(
              "48.64.0.25",
			  "48.64.0.26"
			)
$idracUser = "root"
$idracPwd = "D3ll3mc@mw@cscsg"
$filePath = "//dd9400a.sg.csc/ISOIMAGES/RedHat/rhel-9.4-x86_64-boot.iso"
$fileUser = "raghur2@sg.csc"
$filePwd = "Stan-2780"

foreach ($idrac in $idracIps) {
	Write-Host "Processing $idrac"
	Invoke-Expression "racadm -r $idrac -u $idracUser -p $idracPwd remoteimage -c -u $fileUser -p $filePwd -l $filepath --nocertwarn"
	racadm -r $idrac -u $idracUser -p $idracPwd set iDRAC.VirtualMedia.BootOnce 1 --nocertwarn
	racadm -r $idrac -u $idracUser -p $idracPwd set iDRAC.ServerBoot.FirstBootDevice VCD-DVD --nocertwarn
	racadm -r $idrac -u $idracUser -p $idracPwd serveraction powercycle --nocertwarn
}