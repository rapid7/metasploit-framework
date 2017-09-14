##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  # Exploit mixins should go first
  include Msf::Exploit::Remote::Tcp

  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner

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

  # Skeleton for this section taken from smb2.rb module by @hdm
  # Fingerprint a single host
  def run_host(ip)
    begin
      connect

      # Only accept NT LM 0.12 dialect
      dialects = ['Windows for Workgroups 3.0a', 'NT LM 0.12']
      data     = dialects.collect { |dialect| "\x02" + dialect + "\x00" }.join('')

      pkt = Rex::Proto::SMB::Constants::SMB_NEG_PKT.make_struct
      pkt['Payload']['SMB'].v['Command'] = Rex::Proto::SMB::Constants::SMB_COM_NEGOTIATE
      pkt['Payload']['SMB'].v['Flags1'] = 0x98
      pkt['Payload']['SMB'].v['Flags2'] = 0xc807
      pkt['Payload'].v['Payload']       = data

      pkt['Payload']['SMB'].v['ProcessID']     = rand(0x10000)
      pkt['Payload']['SMB'].v['MultiplexID']   = rand(0x10000)

      sock.put(pkt.to_s)
      res = sock.get_once
      # expecting \xff instead of \xfe
      print_good("#{ip} supports SMBv1") if res && res.index("\xffSMB")
    rescue ::Rex::ConnectionError
    rescue Errno::ECONNRESET
    rescue ::Exception => e
      print_error("#{rhost}: #{e.class} #{e} #{e.backtrace}")
    ensure
      disconnect
    end
  end
end
