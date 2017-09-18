##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  # Exploit mixins should go first
  include Msf::Exploit::Remote::Tcp

  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # Aliases for common classes
  SIMPLE = Rex::Proto::SMB::SimpleClient
  XCEPT  = Rex::Proto::SMB::Exceptions
  CONST  = Rex::Proto::SMB::Constants

  def initialize
    super(
      'Name'        => 'SMBv1 Protocol Detection',
      'Description' => 'Detect systems that support the SMBv1 protocol',
      'Author'      => 'Chance Johnson @loftwing',
      'License'     => MSF_LICENSE
    )

    register_options([ Opt::RPORT(445) ])
  end

  # Modified from smb2 module by @hdm
  # Fingerprint a single host
  def run_host(ip)
    begin
      connect

      # Only accept NT LM 0.12 dialect and WfW3.0
      dialects = ['PC NETWORK PROGRAM 1.0',
                  'LANMAN1.0',
                  'Windows for Workgroups 3.1a',
                  'LM1.2X002',
                  'LANMAN2.1',
                  'NT LM 0.12']
      data     = dialects.collect { |dialect| "\x02" + dialect + "\x00" }.join('')

      pkt = Rex::Proto::SMB::Constants::SMB_NEG_PKT.make_struct
      pkt['Payload']['SMB'].v['Command'] = Rex::Proto::SMB::Constants::SMB_COM_NEGOTIATE
      pkt['Payload']['SMB'].v['Flags1'] = 0x08
      pkt['Payload']['SMB'].v['Flags2'] = 0xc801
      pkt['Payload'].v['Payload']       = data

      pkt['Payload']['SMB'].v['ProcessID']     = rand(0x10000)
      pkt['Payload']['SMB'].v['MultiplexID']   = rand(0x10000)

      sock.put(pkt.to_s)
      res = sock.get_once
      # expecting \xff instead of \xfe
      if res && res.index("\xffSMB")
        print_good("#{ip} supports SMBv1 dialect.")
        report_note(
          host: ip,
          proto: 'tcp',
          sname: 'smb1',
          port: rport,
          type: "supports SMB 1"
        )
      end
    rescue ::Rex::ConnectionError
    rescue EOFError
    rescue Errno::ECONNRESET
    rescue ::Exception => e
      print_error("#{rhost}: #{e.class} #{e} #{e.backtrace}")
    ensure
      disconnect
    end
  end
end
