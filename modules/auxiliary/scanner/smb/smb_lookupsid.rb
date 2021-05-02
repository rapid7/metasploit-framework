##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated

  include Msf::Exploit::Remote::DCERPC

  # Scanner mixin should be near last
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'SMB SID User Enumeration (LookupSid)',
      'Description' => 'Determine what users exist via brute force SID lookups.
        This module can enumerate both local and domain accounts by setting
        ACTION to either LOCAL or DOMAIN',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE,
      'DefaultOptions' =>
        {
          # Samba doesn't like this option, so we disable so we are compatible with
          # both Windows and Samba for enumeration.
          'DCERPC::fake_bind_multi' => false
        },
      'Actions'     =>
        [
          ['LOCAL', { 'Description' => 'Enumerate local accounts' } ],
          ['DOMAIN', { 'Description' => 'Enumerate domain accounts' } ]
        ],
      'DefaultAction' => 'LOCAL'
    )

    register_options(
      [
        OptInt.new('MinRID', [ false, "Starting RID to check", 500 ]),
        OptInt.new('MaxRID', [ false, "Maximum RID to check", 4000 ])
      ],
      self.class
    )

    deregister_options('RPORT')
  end

  # Constants used by this module
  LSA_UUID     = '12345778-1234-abcd-ef00-0123456789ab'
  LSA_VERS     = '0.0'
  LSA_PIPES    = %W{ LSARPC NETLOGON SAMR BROWSER SRVSVC }

  def rport
    @rport || datastore['RPORT']
  end

  def smb_direct
    @smbdirect || datastore['SMBDirect']
  end

  # Locate an available SMB PIPE for the specified service
  def smb_find_dcerpc_pipe(uuid, vers, pipes)
    found_pipe   = nil
    found_handle = nil
    pipes.each do |pipe_name|
      connected = false
      begin
        connect
        smb_login
        connected = true

        handle = dcerpc_handle(
          uuid, vers,
          'ncacn_np', ["\\#{pipe_name}"]
        )

        dcerpc_bind(handle)
        return pipe_name

      rescue ::Interrupt => e
        raise e
      rescue ::Exception => e
        raise e if not connected
      end
      disconnect
    end
    nil
  end

  def smb_parse_sid(data)
    fields = data.unpack('VvvvvVVVVV')
    domain = data[32, fields[3]]
    domain.gsub!("\x00", '')

    if(fields[6] == 0)
      return [nil, domain]
    end

    while(fields[3] % 4 != 0)
      fields[3] += 1
    end

    buff = data[32 + fields[3], data.length].unpack('VCCvNVVVVV')
    sid  = buff[4..8].map{|x| x.to_s }.join("-")
    return [sid, domain]
  end

  def smb_pack_sid(str)
    [1,5,0].pack('CCv') + str.split('-').map{|x| x.to_i}.pack('NVVVV')
  end

  def smb_parse_sid_lookup(data)

    fields = data.unpack('VVVVVvvVVVVV')
    if(fields[0] == 0)
      return nil
    end

    domain = data[44, fields[5]]
    domain.gsub!("\x00", '')

    while(fields[5] % 4 != 0)
      fields[5] += 1
    end

    ginfo = data[44 + fields[5], data.length].unpack('VCCvNVVVV')
    uinfo = data[72 + fields[5], data.length].unpack('VVVVvvVVVVV')

    if(uinfo[3] == 8)
      return [8, nil]
    end

    name = data[112 + fields[5], uinfo[4]]
    name.gsub!("\x00", '')

    [ uinfo[3], name ]
  end

  # Fingerprint a single host
  def run_host(ip)
    [[139, false], [445, true]].each do |info|

    @rport = info[0]
    @smbdirect = info[1]

    lsa_pipe   = nil
    lsa_handle = nil
    begin
      # find the lsarpc pipe
      lsa_pipe = smb_find_dcerpc_pipe(LSA_UUID, LSA_VERS, LSA_PIPES)
      break if not lsa_pipe

      # OpenPolicy2()
      stub =
        NDR.uwstring(ip) +
        NDR.long(24) +
        NDR.long(0) +
        NDR.long(0) +
        NDR.long(0) +
        NDR.long(0) +
        NDR.long(rand(0x10000000)) +
        NDR.long(12) +
        [
          2, # Impersonation
          1, # Context
          0  # Effective
        ].pack('vCC') +
        NDR.long(0x02000000)

      dcerpc.call(44, stub)
      resp = dcerpc.last_response ? dcerpc.last_response.stub_data : nil

      if ! (resp and resp.length == 24)
        print_error("Invalid response from the OpenPolicy request")
        disconnect
        return
      end

      phandle = resp[0,20]
      perror  = resp[20,4].unpack("V")[0]

      # Recent versions of Windows restrict this by default
      if(perror == 0xc0000022)
        disconnect
        return
      end

      if(perror != 0)
        print_error("Received error #{"0x%.8x" % perror} from the OpenPolicy2 request")
        disconnect
        return
      end

      # QueryInfoPolicy(Local)
      stub = phandle + NDR.long(5)
      dcerpc.call(7, stub)
      resp = dcerpc.last_response ? dcerpc.last_response.stub_data : nil
      host_sid, host_name = smb_parse_sid(resp)

      # QueryInfoPolicy(Domain)
      stub = phandle + NDR.long(3)
      dcerpc.call(7, stub)
      resp = dcerpc.last_response ? dcerpc.last_response.stub_data : nil
      domain_sid, domain_name = smb_parse_sid(resp)

      # Store SID, local domain name, joined domain name
      print_status("PIPE(#{lsa_pipe}) LOCAL(#{host_name} - #{host_sid}) DOMAIN(#{domain_name} - #{domain_sid})")

      domain = {
        :name    => host_name,
        :txt_sid => host_sid,
        :users   => {},
        :groups  => {}
      }

      target_sid = case action.name.upcase
      when 'LOCAL'
        host_sid
      when 'DOMAIN'
        # Fallthrough to the host SID if no domain SID was returned
        unless domain_sid
          print_error("No domain SID identified, falling back to the local SID...")
        end
        domain_sid || host_sid
      end

      min_rid = datastore['MinRID']
      # Brute force through a common RID range

      min_rid.upto(datastore['MaxRID']) do |rid|

        stub =
          phandle +
          NDR.long(1) +
          NDR.long(rand(0x10000000)) +
          NDR.long(1) +
          NDR.long(rand(0x10000000)) +
          NDR.long(5) +
          smb_pack_sid(target_sid) +
          NDR.long(rid) +
          NDR.long(0) +
          NDR.long(0) +
          NDR.long(1) +
          NDR.long(0)

        dcerpc.call(15, stub)
        resp = dcerpc.last_response ? dcerpc.last_response.stub_data : nil

        # Skip the "not mapped" error message
        if(resp and resp[-4,4].unpack("V")[0] == 0xc0000073)
          next
        end

        # Stop if we are seeing access denied
        if(resp and resp[-4,4].unpack("V")[0] == 0xc0000022)
          break
        end

        utype,uname = smb_parse_sid_lookup(resp)
        case utype
        when 1
          print_status("USER=#{uname} RID=#{rid}")
          domain[:users][rid] = uname
        when 2
          domain[:groups][rid] = uname
          print_status("GROUP=#{uname} RID=#{rid}")
        else
          print_status("TYPE=#{utype} NAME=#{uname} rid=#{rid}")
        end
      end

      # Store the domain information
      report_note(
        :host => ip,
        :proto => 'tcp',
        :port => rport,
        :type => 'smb.domain.lookupsid',
        :data => domain
      )

      print_status("#{domain[:name].upcase} [#{domain[:users].keys.map{|k| domain[:users][k]}.join(", ")} ]")
      disconnect
      return

    rescue ::Timeout::Error
    rescue ::Interrupt
      raise $!
    rescue ::Rex::ConnectionError
    rescue ::Rex::Proto::SMB::Exceptions::LoginError
      next
    rescue ::Exception => e
      print_line("Error: #{e.class} #{e}")
    end
    end
  end
end
