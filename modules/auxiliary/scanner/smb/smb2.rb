##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

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
      'Name'        => 'SMB 2.0 Protocol Detection',
      'Description' => 'Detect systems that support the SMB 2.0 protocol',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    register_options([ Opt::RPORT(445) ], self.class)
  end

  # Fingerprint a single host
  def run_host(ip)

    begin
      connect

      # The SMB 2 dialect must be there
      dialects = ['PC NETWORK PROGRAM 1.0', 'LANMAN1.0', 'Windows for Workgroups 3.1a', 'LM1.2X002', 'LANMAN2.1', 'NT LM 0.12', 'SMB 2.002', 'SMB 2.???']
      data     = dialects.collect { |dialect| "\x02" + dialect + "\x00" }.join('')

      pkt = Rex::Proto::SMB::Constants::SMB_NEG_PKT.make_struct
      pkt['Payload']['SMB'].v['Command'] = Rex::Proto::SMB::Constants::SMB_COM_NEGOTIATE
      pkt['Payload']['SMB'].v['Flags1'] = 0x18
      pkt['Payload']['SMB'].v['Flags2'] = 0xc853
      pkt['Payload'].v['Payload']       = data

      pkt['Payload']['SMB'].v['ProcessID']     = rand(0x10000)
      pkt['Payload']['SMB'].v['MultiplexID']   = rand(0x10000)

      sock.put(pkt.to_s)
      res = sock.get_once
      if(res and res.index("\xfeSMB"))
        if(res.length >= 124)
          vers  = res[72,2].unpack("CC").map{|c| c.to_s}.join(".")
          ctime = Rex::Proto::SMB::Utils.time_smb_to_unix(*(res[108,8].unpack("VV").reverse))
          btime = Rex::Proto::SMB::Utils.time_smb_to_unix(*(res[116,8].unpack("VV").reverse))
          utime = ctime - btime
          print_status("#{ip} supports SMB 2 [dialect #{vers}] and has been online for #{utime/3600} hours")
          #Add Report
          report_note(
            :host	=> ip,
            :proto => 'tcp',
            :sname	=> 'smb2',
            :port	=> rport,
            :type	=> "supports SMB 2 [dialect #{vers}]",
            :data	=> "supports SMB 2 [dialect #{vers}] and has been online for #{utime/3600} hours"
          )
        else
          print_status("#{ip} supports SMB 2.0")
          #Add Report
          report_note(
            :host	=> ip,
            :proto => 'tcp',
            :sname	=> 'smb2',
            :port	=> rport,
            :type	=> "supports SMB 2.0",
            :data	=> "supports SMB 2.0"
          )
        end
      end

    rescue ::Rex::ConnectionError
    rescue ::Exception => e
      print_error("#{rhost}: #{e.class} #{e} #{e.backtrace}")
    ensure
      disconnect
    end
  end

end
