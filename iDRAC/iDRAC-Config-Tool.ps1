# v2.0 2025-03-05
# This is a script to configure iDRAC on new servers
# Meant for SG CSC. Not for production use.
# Created by Ramanan Raghuraman (ramanan.raghuraman@dell.com) on 2025-02-25

# CAUTION: **** THIS SCRIPT WILL REBOOT THE SERVERS ****

############## Release notes ##############
#
# v2.0 2025-03-05
#    Added functionality to attach virtual media from remote file share (HTTP/NFS/CIFS) and reboot the server
#    Added functionality to detach remote file share virtual media in iDRAC
#    Other minor bugfixes
#
# v1.1 2025-03-02
#    Updated script to check and report errors when running the configuration commands using racadm
#
# v1.0 2025-02
#    Intial release with Configure New Idrac process
#
###########################################



# Function to validate if the input is a valid IP address

### Global Variables
$logfile = "idrac-config-log.txt"

function Display-Menu {

	do {
		Write-Host ""
		Write-Host "Menu"
		Write-Host "----"
		Write-Host ""
		Write-Host "1. Configure New iDRAC"
        Write-Host "2. Update iDRAC Hostname"
		Write-Host "3. Add Local User to iDRAC"
		Write-Host "4. Configure AD on iDRAC"
        Write-Host "5. Attach Virtual Media from Network Share ISO and reboot"
        Write-Host "6. Detach ISO from Virtual Media"
		Write-Host "7. Quit"
		Write-Host ""
		$operation = Read-Host "Please choose one option"
	} while ($operation -notmatch "^[1-7]$")
	return [int]$operation
}


function Validate-IP {
    param (
        [string]$ipAddress
    )

    # Regular expression pattern for validating IPv4 address
    $ipPattern = '^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})){3}$'

    if ($ipAddress -match $ipPattern) {
		return $true
    }
    else {
		return $false
    }
	Write-Host "Unexpected error validating $ipAddress"
	return $false
}

function Validate-Url {
    param (
        [string]$url
    )

    # Regular expression pattern for validating IPv4 address
    $urlPattern = "^[^\s/$.?#][^\s]*\.[^\s.]*$"

    if ($url -match $urlPattern) {
		return $true
    }
    else {
		return $false
    }
	Write-Host "Unexpected error validating $url"
	return $false

}

# Function to make the racadm call and update the idrac.
# This has been written as a seperate function so that if we want to change to redfish or other methods of updating the idrac later, if can be done in one place
# Also if we want to change how idrac command reponses are logged, it can be done here in one place.
function Update-Idrac {
	param (
		[string]$ip,
		[string]$uname,
		[string]$pw,
		[string]$command
	)

    $isError = 0
	
    $fullcmd = "racadm -r $ip -u $uname -p $pw --nocertwarn $command"
    $time = Get-Date -Format "yyyy-MM-dd-HH:mm:ss"
    "$time $fullcmd" >> $logfile
    Write-Host $fullcmd
    Invoke-Expression "$fullcmd	2>&1 >> $logfile"
    if ($LASTEXITCODE -ne 0) {
        Write-Host -ForegroundColor Red "ERROR: racadm command returned error"
        Write-Host -ForegroundColor Red "`tCommand: $fullcmd"
        Write-Host -ForegroundColor Red "`tRefer to $logfile for details" 
        $isError = 1
    }

    return $isError
    
}

function Get-IdracIps {
    
    $input = Read-Host "iDRAC Start IP"
    while (!(Validate-IP -ipAddress $input)) {
        Write-Host "*** Invalid Value ($input) - please input a valid IP address ***"
        $input = Read-Host "iDRAC Start IP"
    }
    $startingIp = $input

    $input = Read-Host "Number of servers"
	while (!($input -match '^\d+$')) {
        Write-Host "*** Invalid Value ($input) - please input a valid number ***"
		$input = Read-Host "Number of servers"
	}
    $numIps = $input

	# Convert the starting IP to an array of integers
	$ipParts = $startingIP -split '\.' | ForEach-Object { [int]$_ }

	# Initialize an array to hold the IP addresses
	$ipArray = @()
	
	for ($i = 0; $i -lt $numIps; $i++) {
		# Calculate the new IP address
		$newIP = $ipParts[0..2] + @(($ipParts[3] + $i) % 256)
		
		# Handle overflow to the next octet
		if ($ipParts[3] + $i -ge 256) {
			$newIP[2]++
			$newIP[3] = ($ipParts[3] + $i) % 256
		}

		# Convert the array back to a string and add to the array
		$ipArray += ($newIP -join '.')
	}

	return $ipArray
}

function Get-Passwords {
    $currentRootPassword = "calvin"
    $newRootPassword = "D3ll3mc@mw@cscsg"

    # Get the current and new password
	if (($input = Read-Host "Enter current root password [$currentRootPassword]") -notmatch "^\s*$") {
        $currentRootPassword = $input
	}
    if (($input = Read-Host "Enter new root password [$newRootPassword]") -notmatch "^\s*$") {
        $newRootPassword = $input
	}

    return @($currentRootPassword, $newRootPassword)
}

function Get-UserAndPw {

    param (
        [string]$component
    )

    # Get the username - can match alphanumeric characeters and also . _ - @ ~ \ or /
    while (($input = Read-Host "$component Username") -notmatch '^[a-zA-Z0-9._\-@~/\\]+$') {
        Write-Host "*** Invalid Value ($input) - please input a valid username ***"
    }
    $uname = $input

    while (($input = Read-Host "$component Password") -notmatch "^[\x20-\x7E]+$") {
        Write-Host "*** Invalid Value ($input) - Please input a valid password ***"
    }
    $pwd = $input

    return @($uname, $pwd)
}

function Get-HostnameParams {
    # Get the information required to set the hostname correctly
    while (($input = Read-Host "Location of Server - Room (poc = p, demo = d)") -notmatch "^[pdPD]$") {
        Write-Host "*** Invalid Value ($input) - please input 'p' or 'd' ***"
    }
    $room = $input.ToLower()

    while (($input = Read-Host "Location of Server - Row (a/b/c)") -notmatch "^[abcABC]$") {
        Write-Host "*** Invalid Value ($input) - please input 'a', 'b', or 'c' ***"
    }
    $row = $input.ToLower()

    while (($input = Read-Host "Location of Server - Rack (1-20)") -notmatch "^([1-9]|1[0-9]|20)$") {
        Write-Host "*** Invalid Value ($input) - please input a number between 1 and 20' ***"
    }
    # set the rack number to "0X" if the rack number is a single digit
	# e.g. rack Number 5 is converted to "05", and number 12 is converted to "12"
    $rack = "{0:D2}" -f [int]$input

    while (($input = Read-Host "Server Model") -notmatch "^[a-z][a-z0-9-]*[a-z0-9]$") {
        Write-Host "*** Invalid Value ($input) - please intput a string of lowercase letters, digits and '-'. Start with a letter, and cannot end with '-' ***"
    }
    $model = $input

    while (($input = Read-Host "Node Starting Number [1]") -notmatch "^((\s*)|([1-9]|[1-9][0-9]))$") {
        Write-Host "*** Invalid Value ($input) - please input a number between 1 and 99' ***"
    }
    if ($input -match "^\s*$") {
        $nodeOffset = "1"
    }
    else {
        $nodeOffset = $input;
    }

    return @("$room$row$rack","$model",[int]$nodeOffset)
}

function Get-DnsNtpLdap {
    $dns1 = "10.204.31.41"
    $dns2 = "10.204.31.42"
    $ntp1 = "10.204.31.2"
    $ntp2 = "10.204.31.3"
    $ldap = "sg.csc"

    $input = Read-Host "DNS Server 1 IP [$dns1]"
    while (($input -notmatch "^\s*$") -and !(Validate-IP -ipAddress $input)) {
        Write-Host "*** Invalid Value ($input) - please input a valid IP"
        $input = Read-Host "DNS Server 1 IP [$dns1]"
    }
    if ($input -notmatch "^\s*$") {
        $dns1 = $input
    }
    
    $input = Read-Host "DNS Server 2 IP [$dns2]"
    while (($input -notmatch "^\s*$") -and !(Validate-IP -ipAddress $input)) {
        Write-Host "*** Invalid Value ($input) - please input a valid IP"
        $input = Read-Host "DNS Server 2 IP [$dns2]"
    }
    if ($input -notmatch "^\s*$") {
        $dns2 = $input
    }
    
    $input = Read-Host "NTP Server 1 IP [$ntp1]"
    while (($input -notmatch "^\s*$") -and !(Validate-IP -ipAddress $input)) {
        Write-Host "*** Invalid Value ($input) - please input a valid IP"
        $input = Read-Host "NTP Server 1 IP [$ntp1]"
    }
    if ($input -notmatch "^\s*$") {
        $ntp1 = $input
    }
    
    $input = Read-Host "NTP Server 2 IP [$ntp2]"
    while (($input -notmatch "^\s*$") -and !(Validate-IP -ipAddress $input)) {
        Write-Host "*** Invalid Value ($input) - please input a valid IP"
        $input = Read-Host "NTP Server 2 IP [$ntp2]"
    }
    if ($input -notmatch "^\s*$") {
        $ntp2 = $input
    }

    #$input = Read-Host "LDAP Server IP or URL [$ldap]"
    #while (($input -notmatch "^\s*$") -and !(Validate-IP -ipAddress $input) -and !(Validate-Url -url $input)) {
    #    Write-Host "*** Invalid Value ($input) - please input a valid IP or URL"
    #    $input = Read-Host "LDAP Server IP or URL [$ldap]"
    #}
    #if ($input -notmatch "^\s*$") {
    #    $ldap = $input
    #}

    return @($dns1, $dns2, $ntp1, $ntp2, $ldap)
}

function Get-FileShare {
    
    Write-Host ""
    Write-Host "iDRAC supports CIFS, NFS, HTTP and HTTPS protocols - see the valid formats below:"
    Write-Host -nonewline -ForegroundColor Yellow "`tCIFS: "
    Write-Host "//<server name or IP>/path/filename"
    Write-Host -nonewline -ForegroundColor Yellow "`tNFS: "
    Write-Host "<server name or IP>:/path/filename"
    Write-Host -nonewline -ForegroundColor Yellow "`tHTTP: "
    Write-Host "http[s]://<server name or IP>/path/filename"
    Write-Host "Do not use backslash '\' character"
    Write-Host ""
    do {
        $input = Read-Host "Fileshare path"
        if ($input -match "^https?:\/\/[^\s/$.?#].[^\s]*$") {
            $type = "http"
            $path = $input
            break
        }
        elseif ($input -match "^(//)[a-zA-Z0-9._\-]+(/[a-zA-Z0-9._\-~]+)*/?$") {
            $type = "cifs"
            $path = $input
            break
        }
        elseif ($input -match "^[a-zA-Z0-9._\-]+:(/[a-zA-Z0-9._\-~]+)+$") {
            $type = "nfs"
            $path = $input
            break
        }
        else {
            Write-Host "*** Invalid Value ($input) - please input a valid remote file path"
        }
    } while ($true)

    if ($type -eq "http") {
        return @($type, $path, $null, $null)
    }
    elseif ($type -eq "nfs") {
        $userpw = Get-UserAndPw -component "NFS share"
    }
    elseif ($type -eq "cifs") {
        $userpw = Get-UserAndPw -component "CIFS share"
    }
    else {
        Write-Host -ForegroundColor Red "Unexpected Error!"
    }

    return @($type, $path, $userpw[0], $userpw[1])
}

function Configure-RootPassword {
    param (
        [string]$idracIp,
        [string]$currentPw,
        [string]$newPw
    )

    Write-Host -ForegroundColor Yellow "`Changing root password"
    #racadm -r $idracIp -u root -p $currentRootPw --nocertwarn set idrac.Users.2.Password $newPw
    $isError = Update-Idrac -ip $idracIp -uname "root" -pw $currentPw -command "set idrac.Users.2.Password $newPw"

    return $isError

}

function Configure-DnsNtp {

    param (
        [string]$idracIp,
        [string]$rootPw,
        [string]$dns1,
        [string]$dns2,
        [string]$ntp1,
        [string]$ntp2
    )

    $isError = 0

    Write-Host -ForegroundColor Yellow "Configuring DNS ($dns1, $dns2)"

	# set the DNS Server IPs
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.ipv4static.dns1 $dns1")
	$isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.ipv4static.dns2 $dns2")
	#racadm -r $idracIp -u root -p $rootPw --nocertwarn set idrac.ipv4static.dns1 $dns1
	#racadm -r $idracIp -u root -p $rootPw --nocertwarn set idrac.ipv4static.dns2 $dns2


    Write-Host -ForegroundColor Yellow "Configuring NTP ($ntp1, $ntp2) and Setting Timezone to Asia/Singapore"
	# set timezone to SGT and enable NTP
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.time.timezone Asia/Singapore")
	$isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.NTPConfigGroup.NTPEnable 1")
	$isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.NTPConfigGroup.NTP1 $ntp1")
	$isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.NTPConfigGroup.NTP2 $ntp2")
	#racadm -r $idracIp -u root -p $rootPw --nocertwarn set idrac.time.timezone Asia/Singapore
	#racadm -r $idracIp -u root -p $rootPw --nocertwarn set idrac.NTPConfigGroup.NTPEnable 1
	#racadm -r $idracIp -u root -p $rootPw --nocertwarn set idrac.NTPConfigGroup.NTP1 $ntp1
	#racadm -r $idracIp -u root -p $rootPw --nocertwarn set idrac.NTPConfigGroup.NTP2 $ntp2

    return $isError
}

function Configure-Hostname {

    param (
        [string]$idracIp,
        [string]$rootPw,
        [string]$location,
        [string]$model,
        [int]$nodeNumber
    )

	# set the idrac hostname
	# Get the serviceTag from the host
    Write-Host -ForegroundColor Yellow "Getting Svctag from server"
	$svcTag = ([String](racadm -r $idracIp -u root -p $rootPw --nocertwarn getsvctag)).Trim()

	# set the node number to "0X" if the nodenumber is a single digit
    # e.g. nodeNumber 5 is converted to "05", and number 12 is converted to "12"
	$formattedNumber = "{0:D2}" -f $nodeNumber

	#construct the hostname and set it in iDRAC
	$hostname = "idrac-$location-$model-node$formattedNumber-$svcTag"
    Write-Host -ForegroundColor Yellow "Setting server hostname to $hostname"
	$isError = Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set iDRAC.NIC.DNSRacName $hostname"
    #racadm -r $idracIp -u root -p $rootPw --nocertwarn set iDRAC.NIC.DNSRacName $hostname

    return $isError
}

function Configure-DirectoryService {
	
    param (
        [string]$idracIp,
        [string]$rootPw,
        [string]$domain,
        [string]$server1,
        [string]$server2
    )

    $isError = 0

    Write-Host -ForegroundColor Yellow "Setting up directory service to domain $domain using $server1 and $server2"
    
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.activedirectory.AuthTimeout 15")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.activedirectory.CertValidationEnable Disabled")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.activedirectory.Connection LDAPS")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.activedirectory.DCLookupByUserDomain Enabled")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.activedirectory.DCLookupDomainName $domain")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.activedirectory.DCLookupEnable Disabled")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.userdomain.1.name $domain")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.activedirectory.DomainController1 $server1")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.activedirectory.DomainController2 $server2")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.activedirectory.Enable Enabled")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.activedirectory.GCLookupEnable Disabled")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.activedirectory.GCRootDomain sg.csc")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.activedirectory.GlobalCatalog1 $server1")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.activedirectory.GlobalCatalog2 $server2")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.activedirectory.RacDomain $domain ")
    #$isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.activedirectory.RSASecurID2FAAD Disabled")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.activedirectory.Schema 2")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.activedirectory.SSOEnable Disabled")

    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.adgroup.1.domain sg.csc")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.adgroup.1.name idrac-admin")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.adgroup.1.privilege 0x1ff")

    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.adgroup.2.domain sg.csc")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.adgroup.2.name idrac-operator")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.adgroup.2.privilege 0x0f3")

    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.adgroup.3.domain sg.csc")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.adgroup.3.name idrac-readonly")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set idrac.adgroup.3.privilege 0x001")

    return $isError

}

function Configure-BiosTimezone {
    param (
        [string]$idracIp,
        [string]$rootPw
    )

    $isError = 0

    Write-Host -ForegroundColor Yellow "Setting BIOS Timezone to UTC+8 on Server $idracIp"
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "set bios.miscsettings.timezone UTCP0800")
    $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "jobqueue create BIOS.Setup.1-1")

    if (isError -gt 0) {
        Write-Host -ForegroundColor Red "Errors encountered setting BIOS Timezone on $idracIP. Skipping server reboot"
    }
    else {
        Write-Host -ForegroundColor Yellow "Rebooting server $idracIp"
        $isError += (Update-Idrac -ip $idracIp -uname "root" -pw $rootPw -command "serveraction powercycle")
    }
    return $isError
}

function Configure-FileShare {
    param (
        [string]$idracIp,
        [string]$idracUname,
        [string]$idracPwd,
        [string]$shareType,
        [string]$sharePath,
        [string]$shareUname,
        [string]$sharePw
    )

    $isError = 0

    Write-Host -ForegroundColor Yellow "Setting remote share to $sharePath on Server $idracIp"
    $isError += (Update-Idrac -ip $idracIp -uname $idracUname -pw $idracPwd -command "remoteimage -c -u $shareUname -p $sharePw -l $sharePath")
    $isError += (Update-Idrac -ip $idracIp -uname $idracUname -pw $idracPwd -command "set iDRAC.VirtualMedia.BootOnce 1")
    $isError += (Update-Idrac -ip $idracIp -uname $idracUname -pw $idracPwd -command "set iDRAC.ServerBoot.FirstBootDevice VCD-DVD")

    if ($isError -gt 0) {
        Write-Host -ForegroundColor Red "Errors encountered setting remote share path on $idracIP. Skipping server reboot"
    }
    else {
        Write-Host -ForegroundColor Yellow "Rebooting server $idracIp"
        $isError += (Update-Idrac -ip $idracIp -uname $idracUname -pw $idracPwd -command "serveraction powercycle")
    }

    return $isError
}

function Configure-Idrac {

    Write-Host "`n`n"
    Write-Host "This operation will perform the following tasks:"
    Write-Host "`t-Update the default root password to the CSC SG standard root password"
    Write-Host "`t-Configure the NTP Server IPs and Timezone setting"
    Write-Host "`t-Configure the DNS Server IPs"
    Write-Host "`t-Configure the Hostname of the server using our standard naming convention"
    Write-Host "`t-Set up AD integration so that you can log in with your AD account"
    Write-Host -NoNewline "`t-Optional: Configure the BIOS timezone correctly." 
    Write-Host -ForegroundColor Red " | *NOTE:* This will require a server reboot!"
    Write-Host "`n`n"


    do {

        # Get Range of IPs for the iDRACs to configure
	    $idracArray = Get-idracIps
	    
        $rootPasswords = Get-Passwords

        $hostnameParams = Get-HostnameParams

        $dnsNtpLdap = Get-DnsNtpLdap
    
        Write-Host "`n`n`n"
        Write-Host "The following values will be configured:"
        Write-Host -NoNewline "`tServer IPs: "
        foreach ($idrac in $idracArray) {
            Write-Host -NoNewline "$idrac, "
        }
        Write-Host ""
        Write-Host "`tRoot password: $($rootPasswords[1])"
        Write-Host "`tHostname Prefix: $($hostnameParams[0])-$($hostnameParams[1])-node<NN>-<svctag>"
        Write-Host "`tDNS Servers: $($dnsNtpLdap[0]), $($dnsNtpLdap[1])"
        Write-Host "`tNTP Servers: $($dnsNtpLdap[2]), $($dnsNtpLdap[3])"
        Write-Host "`tAD Server: $($dnsNtpLdap[4])"
        Write-Host ""
        $input = Read-Host "Is this correct (y/n)"
    } while (($input -ne "y") -and ($input -ne "Y")) 


    $numErrors = 0

    $nodeNumber = $hostnameParams[2]
    foreach ($idrac in $idracArray) {
        Write-Host ""
        Write-Host ""
        Write-Host -ForegroundColor Cyan  "Starting Processing $idrac"
        Write-Host "---------------------------------------"
        Write-Host ""
        
        $numErrors += Configure-RootPassword -idracIp $idrac -currentPw $rootPasswords[0] -newPw $rootPasswords[1]
        Write-Host ""
    
        $numErrors += Configure-DnsNtp -idracIp $idrac -rootPw $rootPasswords[1] -dns1 $dnsNtpLdap[0] -dns2 $dnsNtpLdap[1] -ntp1 $dnsNtpLdap[2] -ntp2 $dnsNtpLdap[3]
        Write-Host ""
    
        $numErrors += Configure-Hostname -idracIp $idrac -rootPw $rootPasswords[1] -location $hostnameParams[0] -model $hostnameParams[1]  -nodeNumber $nodeNumber      
        $nodeNumber++
        Write-Host ""
    
        $numErrors += Configure-DirectoryService -idracIp $idrac -rootPw $rootPasswords[1] -domain "sg.csc" -server1 "ad-1.sg.csc" -server2 "ad-2.sg.csc"
        Write-Host ""
    }

    Write-Host "The following items have been configured:`n`t-Updated root password`n`t-Hostname`n`t-NTP and Timezone`n`t-DNS`n`t-AD Integration"

    Write-Host "The BIOS Timezone setting has not yet been set." 
    Write-Host -ForegroundColor Red "CAUTION! Setting this value will require a reboot of the servers." 
    while (($input = Read-Host "Do you want to proceed (y/n)") -notmatch "^[ynYN]$") {
         Write-Host "*** Invalid Value ($input) - please input 'y' or 'n' ***"
    }
    $proceed = $input.ToLower()
    if ($proceed -eq "y") {
        foreach ($idrac in $idracArray) {
            $numErrors += Configure-BiosTimezone -idracIp $idrac -rootPw $rootPasswords[1]
        }
    }


    Write-Host ""
    Write-Host ""
    if ($numErrors -gt 0) {
        Write-Host -ForegroundColor Yellow "--------------------------------------------------------------------------------------------------"
        Write-Host -ForegroundColor Yellow "# Operation completed with a total of $numErrors Error(s). Refer to $logfile for more details #"
        Write-Host -ForegroundColor Yellow "--------------------------------------------------------------------------------------------------"
    }
    else {
        Write-Host -ForegroundColor Green "-------------------------------------"
        Write-Host -ForegroundColor Green "# Operation completed successfully! #"
        Write-Host -ForegroundColor Green "-------------------------------------"
    }

    Write-Host
    $null = Read-Host "Press Enter to Continue"
    Write-Host

}

function Configure-AttachVirtualMedia {
    Write-Host "`n`n"
    Write-Host "This operation will perform the following tasks:"
    Write-Host "`t-Attach an ISO file to the Remote File Share 1 of the iDRAC"
    Write-Host "`t-Set the server to do a one-shot boot from the Virtual CD/DVD Drive"
    Write-Host "`t-Powercycle the server to let it boot into the mounted ISO"
    Write-Host "`n`n"

    do {
        # Get Range of IPs for the iDRACs to configure
	    $idracArray = Get-idracIps
        $idracUnamePw = Get-UserAndPw -component "iDRAC"
        $shareInfo = Get-Fileshare
        
        Write-Host "`n`n`n"
        Write-Host "The following configuration values will be used:"
        Write-Host -NoNewline "`tServer IPs: "
        foreach ($idrac in $idracArray) {
            Write-Host -NoNewline "$idrac, "
        }
        Write-Host ""
        Write-Host "`tiDRAC Username: $($idracUnamePw[0])"
        Write-Host "`tiDRAC Password: $($idracUnamePw[1])"
        Write-Host "`tPath to ISO: $($shareInfo[1])"
        Write-Host "`tFileshare Username: $($shareInfo[2])"
        Write-Host "`tFileshare Password: $($shareInfo[3])"
        Write-Host ""
        $input = Read-Host "Is this correct (y/n)"
    } while (($input -ne "y") -and ($input -ne "Y")) 

    
    $numErrors = 0
    foreach ($idrac in $idracArray) {
        Write-Host ""
        Write-Host ""
        Write-Host -ForegroundColor Cyan  "Starting Processing $idrac"
        Write-Host "---------------------------------------"
        Write-Host ""
        
        $numErrors += Configure-FileShare -idracIp $idrac -idracUname $idracUnamePw[0] -idracPwd $idracUnamePw[1] -shareType $shareInfo[0] -sharePath $shareInfo[1] -shareUname $shareInfo[2] -sharePw $shareInfo[3]
    }

    Write-Host ""
    Write-Host ""
    if ($numErrors -gt 0) {
        Write-Host -ForegroundColor Yellow "--------------------------------------------------------------------------------------------------"
        Write-Host -ForegroundColor Yellow "# Operation completed with a total of $numErrors Error(s). Refer to $logfile for more details #"
        Write-Host -ForegroundColor Yellow "--------------------------------------------------------------------------------------------------"
    }
    else {
        Write-Host -ForegroundColor Green "-------------------------------------"
        Write-Host -ForegroundColor Green "# Operation completed successfully! #"
        Write-Host -ForegroundColor Green "-------------------------------------"
    }

    Write-Host
    $null = Read-Host "Press Enter to Continue"
    Write-Host
}

function Configure-DetachVirtualMedia {
    Write-Host "`n`n"
    Write-Host "This operation will perform the following tasks:"
    Write-Host "`t-Detach the Remote File Share mounted as Virtual Media on the iDRAC"
    Write-Host "`n`n"

    do {
        # Get Range of IPs for the iDRACs to configure
	    $idracArray = Get-idracIps
        $idracUnamePw = Get-UserAndPw -component "iDRAC"
        
        Write-Host "`n`n`n"
        Write-Host "The following configuration values will be used:"
        Write-Host -NoNewline "`tServer IPs: "
        foreach ($idrac in $idracArray) {
            Write-Host -NoNewline "$idrac, "
        }
        Write-Host ""
        Write-Host "`tiDRAC Username: $($idracUnamePw[0])"
        Write-Host "`tiDRAC Password: $($idracUnamePw[1])"
        Write-Host ""
        $input = Read-Host "Is this correct (y/n)"
    } while (($input -ne "y") -and ($input -ne "Y")) 

    
    $numErrors = 0
    foreach ($idrac in $idracArray) {
        Write-Host ""
        Write-Host ""
        Write-Host -ForegroundColor Cyan  "Starting Processing $idrac"
        Write-Host "---------------------------------------"
        Write-Host ""
        
        $numErrors += Update-Idrac -ip $idrac -uname $idracUnamePw[0] -pw $idracUnamePw[1] -command "remoteimage -d"
    }

    Write-Host ""
    Write-Host ""
    if ($numErrors -gt 0) {
        Write-Host -ForegroundColor Yellow "--------------------------------------------------------------------------------------------------"
        Write-Host -ForegroundColor Yellow "# Operation completed with a total of $numErrors Error(s). Refer to $logfile for more details #"
        Write-Host -ForegroundColor Yellow "--------------------------------------------------------------------------------------------------"
    }
    else {
        Write-Host -ForegroundColor Green "-------------------------------------"
        Write-Host -ForegroundColor Green "# Operation completed successfully! #"
        Write-Host -ForegroundColor Green "-------------------------------------"
    }

    Write-Host
    $null = Read-Host "Press Enter to Continue"
    Write-Host
}



###### Main script entry point #######

Write-Host "/---------------------------------\"
Write-Host "| iDRAC Configuration Script v1.0 |"
Write-Host "| Dell CSC, Singapore             |"
Write-Host "\---------------------------------/"

do {
	$userChoice = Display-Menu
	
	switch ($userChoice) {
		1 {
			#Write-Host "Configuring New idrac"
			Configure-Idrac
		}
        2 { 
            Write-Host "Changing host name - Coming soon..."
        }
		3 { 
            Write-Host "Add new user to idrac - Coming soon..." 
        }
		4 { 
            Write-Host "Configure LDAP - Coming soon..." 
        }
        5 {
            #Write-Host "Attaching Network Share ISO to Virtual Media"
            Configure-AttachVirtualMedia
        }
        6 {
            #Write-Host "Detaching Network Share ISO from Virtual Media"
            Configure-DetachVirtualMedia
        }
		7 {
            Write-Host "Quitting..." 
            exit
        }
		default { Write-Host "Unexpected error: Please try again" 
        }
	}
} while ($true)



#
## Command to add extra user and set operator privilege.
##foreach ($idrac in $idracIps) {
##	racadm -r $idrac -u root -p $currentRootPassword --nocertwarn set idrac.Users.4.UserName "sbi-poc"
##	racadm -r $idrac -u root -p $currentRootPassword --nocertwarn set idrac.Users.4.Password $newRootPassword
##	racadm -r $idrac -u root -p $currentRootPassword --nocertwarn set idrac.Users.4.Privilege 0xf1
##	racadm -r $idrac -u root -p $currentRootPassword --nocertwarn set idrac.Users.4.Enable Enabled
##}
#
## Command to perform power action on iDRAC
##foreach ($idrac in $idracIps) {
##  racadm -r $idrac -u $idracUser -p $idracPwd serveraction powerup --nocertwarn
##}