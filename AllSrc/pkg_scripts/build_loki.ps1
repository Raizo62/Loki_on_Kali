$version = "nightly"
$svn = "C:\Program Files\TortoiseSVN\bin\svn"
$repo = "http://c0decafe.de/svn/codename_loki"
$python = "c:\Python26\python.exe"
$tmp = "C:\loki_temp\"
$vsc = "C:\Program Files\Microsoft Visual Studio 10.0\VC\vcvarsall.bat"
$mt = "C:\Program Files\Microsoft SDKs\Windows\v7.0A\bin\mt.exe"
$inno = "C:\Program Files\Inno Setup 5\Compil32.exe"
$davcp = "C:\Program Files\DavCopy\DavCopy.exe"
$user = "user"

function set_acl($path) {
	$Acl = Get-Acl $path
	$Ar = New-Object  system.security.accesscontrol.filesystemaccessrule($user,"FullControl","Allow")
	$Acl.SetAccessRule($Ar)
	Get-ChildItem $path -recurse -Force | Set-Acl -AclObject $Acl
}

if (Test-Path $tmp) {
	"Build dir exists";
    if (Test-Path $tmp/out) {
        "Removing old Output Directory"
        rm -r $tmp/out
    }
} else {
	"Creating new build dir";
	New-Item $tmp  -type directory
	"Setting Access rights";
	set_acl $tmp
}

#"Checkout trunk";
#&$svn export $repo/trunk $tmp\trunk

"Updating trunk";
$Revision = ((&$svn up $tmp\trunk | Select-String "revision") -split("revision "))[1] -replace("\.", $null)

"At revision $Revision.";

if (Test-Path $tmp\loki-$version-r$Revision.exe) {
    "Installer for Revision $Revision found, exiting";
    exit
}

"Setting Path";
Push-Location $tmp\trunk
"Setting ENV";
&$vsc

"Creating output folder";
New-Item $tmp\out  -type directory
"Setting Access rights";
set_acl $tmp\out

#"Preparing output folder";
#&$svn export $repo/packages/win32/loki-win32/etc $tmp\out\etc
#&$svn export $repo/packages/win32/loki-win32/lib $tmp\out\lib

if (Test-Path $tmp/deps) {
    "Dependencies existing";
} else {
    "Getting dependencies";
    New-Item $tmp\deps -type directory
    set_acl $tmp\deps
    &$svn export $repo/packages/win32/deps/vcredist_x86.exe $tmp\deps\
    &$svn export $repo/packages/win32/deps/WinPcap_4_1_2.exe $tmp\deps\
}

"Building Lib";
&$python setup-win32_lib.py build

"Moving Lib in place";
Move-Item $tmp\trunk\build\lib.win32-2.6\loki_bindings\ospfmd5\ospfmd5bf.pyd $tmp\out\ospfmd5bf.pyd
set_acl $tmp\out\ospfmd5bf.pyd
Move-Item $tmp\trunk\build\lib.win32-2.6\loki_bindings\tcpmd5\tcpmd5bf.pyd $tmp\out\tcpmd5bf.pyd
set_acl $tmp\out\tcpmd5bf.pyd

"Building Exe"
&$python setup-win32_exe.py build_exe

"Moving Exe in place";
foreach ($i in Get-ChildItem $tmp\trunk\build\exe.win32-2.6\) {
	Move-Item $tmp\trunk\build\exe.win32-2.6\$i $tmp\out -force
	set_acl $tmp/out/$i
}

"Removing bad modules";
Remove-Item $tmp\out\modules\module_802_1X*
Remove-Item $tmp\out\modules\module_wlccp*
Remove-Item $tmp\out\modules\module_mpls*
Remove-Item $tmp\out\modules\module_snmp*
Remove-Item $tmp\out\modules\module_test*

"Setting Exe Manifest";
&$mt -manifest $tmp\trunk\pkg_scripts\loki_gtk.exe.manifest -outputresource:$tmp\out\loki_gtk.exe;#1

"Creating Installer";
$args = "/cc $tmp\trunk\pkg_scripts\inno_setup.iss"
$proc = Start-Process $inno $args -wait

"Moving Installer in place";
Move-Item $tmp\trunk\pkg_scripts\Output\setup.exe $tmp\loki-$version-r$Revision.exe
set_acl $tmp\loki-$version-r$Revision.exe

########################################
#Webdav Access with PowerShell
########################################

#Put the complete path of the file that you want to upload
$file = "$tmp\loki-$version-r$Revision.exe"

#Put the url without the last "/"
$url  = "http://c0decafe.de/cal"

#Provide User and Pwd for Webdav Access
$user = "************"
$pass = "************"

#######################################
#Script
#######################################

#Adding the name of the file at the end of the URL
$url += "/" + $file.split('\')[(($file.split("\")).count - 1)]

#Connecting to WebDav
Write-Host "File upload started"

# Set binary file type
Set-Variable -name adFileTypeBinary -value 1 -option Constant

$objADOStream = New-Object -ComObject ADODB.Stream
$objADOStream.Open()
$objADOStream.Type = $adFileTypeBinary
$objADOStream.LoadFromFile("$file")
$arrbuffer = $objADOStream.Read()

$objXMLHTTP = New-Object -ComObject MSXML2.ServerXMLHTTP
$objXMLHTTP.Open("PUT", $url, $False, $user, $pass)
$objXMLHTTP.send($arrbuffer)

Write-Host "File upload finished"

"Resetting Path";
Pop-Location
