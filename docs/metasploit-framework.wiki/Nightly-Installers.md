Installers are built nightly for macOS, Windows (64-bit) and Linux.  These installers include dependencies (like Ruby and PostgreSQL) and integrate with your package manager, so they're easy to update.

## Installing Metasploit on Linux / macOS

The following script invocation will import the Rapid7 signing key and setup the package for supported Linux and macOS systems:

```sh
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
  chmod 755 msfinstall && \
  ./msfinstall
```

Once installed, you can launch msfconsole as ```/opt/metasploit-framework/bin/msfconsole``` from a terminal window, or depending on your environment, it may already be in your path and you can just run it directly. On first run, a series of prompts will help you setup a database and add Metasploit to your local PATH if it is not already.

These packages integrate into your package manager and can be updated with the ```msfupdate``` command, or with your package manager. On first start, these packages will automatically setup the database or use your existing database.

### Linux manual installation

Linux packages are built nightly for .deb (i386, amd64, armhf, arm64) and .rpm (64-bit x86) systems. Debian/Ubuntu packages are available at <https://apt.metasploit.com> and CentOS/Redhat/Fedora packages are located at <https://rpm.metasploit.com>.

### macOS manual installation

The latest OS X installer package can also be downloaded directly here: <https://osx.metasploit.com/metasploitframework-latest.pkg>, with the last 8 builds archived at <https://osx.metasploit.com/>. Simply download and launch the installer to install Metasploit Framework with all of its dependencies.

## Installing Metasploit on Windows

Download the [latest Windows installer](https://windows.metasploit.com/metasploitframework-latest.msi) or [view older builds](https://windows.metasploit.com/).
To install, download the `.msi` package, adjust your Antivirus as-needed to ignore `c:\metasploit-framework` and execute the installer by right-clicking the installer file and selecting "Run as Administrator".
The msfconsole command and all related tools will be added to the system `%PATH%` environment variable.

### Windows Anti-virus software flags the contents of these packages!

If you downloaded Metasploit from us, there is no cause for alarm.  We pride ourselves on offering the ability for our customers and followers to have the same toolset that the hackers have so that they can test systems more accurately.  Because these (and the other exploits and tools in Metasploit) are identical or very similar to existing malicious toolsets, they can be used for nefarious purposes, and they are often flagged and automatically removed by antivirus programs, just like the malware they mimic.

### Windows silent installation

The PowerShell below will download and install the framework, and is suitable for automated Windows deployments. Note that, the installer will be downloaded to `$DownloadLocation` and won't be deleted after the script has run.
```powershell
[CmdletBinding()]
Param(
    $DownloadURL = "https://windows.metasploit.com/metasploitframework-latest.msi",
    $DownloadLocation = "$env:APPDATA/Metasploit",
    $InstallLocation = "C:\Tools",
    $LogLocation = "$DownloadLocation/install.log"
)

If(! (Test-Path $DownloadLocation) ){
    New-Item -Path $DownloadLocation -ItemType Directory
}

If(! (Test-Path $InstallLocation) ){
    New-Item -Path $InstallLocation -ItemType Directory
}

$Installer = "$DownloadLocation/metasploit.msi"

Invoke-WebRequest -UseBasicParsing -Uri $DownloadURL -OutFile $Installer

& $Installer /q /log $LogLocation INSTALLLOCATION="$InstallLocation"
```

## Improving these installers

Feel free to review and help improve [the source code for our installers](https://github.com/rapid7/metasploit-omnibus).
