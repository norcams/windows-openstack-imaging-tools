$ErrorActionPreference = "Stop"
$resourcesDir = "$ENV:SystemDrive\UnattendResources"

try
{
    $wallpaper = "$resourcesDir\Wallpaper.jpg"
    if(Test-Path $wallpaper)
    {
        $Host.UI.RawUI.WindowTitle = "Configuring wallpaper..."

        # Put the wallpaper in place
        $wallpaper_dir = "$ENV:SystemRoot\web\Wallpaper\Cloudbase"
        if (!(Test-Path $wallpaper_dir))
        {
            mkdir $wallpaper_dir
        }

        copy "$wallpaper" "$wallpaper_dir\Wallpaper-Cloudbase-2013.jpg"
        $gpoZipPath = "$resourcesDir\GPO.zip"
        foreach($item in (New-Object -com shell.application).NameSpace($gpoZipPath).Items())
        {
            $yesToAll = 16
            (New-Object -com shell.application).NameSpace("$ENV:SystemRoot\System32\GroupPolicy").copyhere($item, $yesToAll)
        }
    }

    # Enable ping (ICMP Echo Request on IPv4 and IPv6)
    netsh advfirewall firewall set rule name = "File and Printer Sharing (Echo Request - ICMPv4-In)" new enable=yes
    netsh advfirewall firewall set rule name = "File and Printer Sharing (Echo Request - ICMPv6-In)" new enable=yes

    # Disable Network discovery
    netsh advfirewall firewall set rule group = "Network Discovery" new enable=No
}
catch
{
    $host.ui.WriteErrorLine($_.Exception.ToString())
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    throw
}
