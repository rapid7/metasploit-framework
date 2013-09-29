##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB
  include Msf::Exploit::Remote::SMB::Authenticated

  include Msf::Exploit::Remote::DCERPC

  # Scanner mixin should be near last
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'SMB User Enumeration (SAM EnumUsers)',
            'Description' => 'Determine what local users exist via the SAM RPC service',
            'Author'      => 'hdm',
            'License'     => MSF_LICENSE,
            'DefaultOptions' => {
                'DCERPC::fake_bind_multi' => false
            }
        )
    )

    deregister_options('RPORT', 'RHOST')
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

  def smb_pack_sid(str)
    [1,5,0].pack('CCv') + str.split('-').map{|x| x.to_i}.pack('NVVVV')
  end

  def smb_parse_sam_domains(data)
    ret = []
    idx = 0

    cnt = data[8, 4].unpack("V")[0]
    return ret if cnt == 0
    idx += 20
    idx += 12 * cnt

    1.upto(cnt) do
      v = data[idx,data.length].unpack('V*')
      l = v[2] * 2

      while(l % 4 != 0)
        l += 1
      end

      idx += 12
      ret << data[idx, v[2] * 2].gsub("\x00", '')
      idx += l
    end
    ret
  end

  def smb_parse_sam_users(data)
    ret = {}
    rid = []
    idx = 0

    cnt = data[8, 4].unpack("V")[0]
    return ret if cnt == 0
    idx += 20

    1.upto(cnt) do
      v = data[idx,12].unpack('V3')
      rid << v[0]
      idx += 12
    end

    1.upto(cnt) do
      v = data[idx,32].unpack('V*')
      l = v[2] * 2

      while(l % 4 != 0)
        l += 1
      end

      uid = rid.shift

      idx += 12
      ret[uid] = data[idx, v[2] * 2].gsub("\x00", '')
      idx += l
    end

    ret
  end

  @@sam_uuid     = '12345778-1234-abcd-ef00-0123456789ac'
  @@sam_vers     = '1.0'
  @@sam_pipes    = %W{ SAMR LSARPC NETLOGON BROWSER SRVSVC }

  # Fingerprint a single host
  def run_host(ip)

    [[139, false], [445, true]].each do |info|

    datastore['RPORT'] = info[0]
    datastore['SMBDirect'] = info[1]

    sam_pipe   = nil
    sam_handle = nil
    begin
      # Find the SAM pipe
      sam_pipe = smb_find_dcerpc_pipe(@@sam_uuid, @@sam_vers, @@sam_pipes)
      break if not sam_pipe

      # Connect4
      stub =
        NDR.uwstring("\\\\" + ip) +
        NDR.long(2) +
        NDR.long(0x30)

      dcerpc.call(62, stub)
      resp = dcerpc.last_response ? dcerpc.last_response.stub_data : nil

      if ! (resp and resp.length == 24)
        print_error("#{ip} Invalid response from the Connect5 request")
        disconnect
        return
      end

      phandle = resp[0,20]
      perror  = resp[20,4].unpack("V")[0]

      if(perror == 0xc0000022)
        disconnect
        return
      end

      if(perror != 0)
        print_error("#{ip} Received error #{"0x%.8x" % perror} from the OpenPolicy2 request")
        disconnect
        return
      end

      # EnumDomains
      stub = phandle + NDR.long(0) + NDR.long(8192)
      dcerpc.call(6, stub)
      resp = dcerpc.last_response ? dcerpc.last_response.stub_data : nil
      domlist = smb_parse_sam_domains(resp)
      domains = {}

      # LookupDomain
      domlist.each do |domain|
        next if domain == 'Builtin'

        # Round up the name to match NDR.uwstring() behavior
        dlen = (domain.length + 1) * 2

        # The SAM functions are picky on Windows 2000
        stub =
          phandle +
          [(domain.length + 0) * 2].pack("v") + # NameSize
          [(domain.length + 1) * 2].pack("v") + # NameLen (includes null)
          NDR.long(rand(0x100000000)) +
          [domain.length + 1].pack("V") +	      # MaxCount (includes null)
          NDR.long(0) +
          [domain.length + 0].pack("V") +	      # ActualCount (ignores null)
          Rex::Text.to_unicode(domain)          # No null appended

        dcerpc.call(5, stub)
        resp    = dcerpc.last_response ? dcerpc.last_response.stub_data : nil
        raw_sid = resp[12, 20]
        txt_sid = raw_sid.unpack("NVVVV").join("-")

        domains[domain] = {
          :sid_raw => raw_sid,
          :sid_txt => txt_sid
        }
      end


      # OpenDomain, QueryDomainInfo, CloseDomain
      domains.each_key do |domain|

        # Open
        stub =
          phandle +
          NDR.long(0x00000305) +
          NDR.long(4) +
          [1,4,0].pack('CvC') +
          domains[domain][:sid_raw]

        dcerpc.call(7, stub)
        resp    = dcerpc.last_response ? dcerpc.last_response.stub_data : nil
        dhandle = resp[0,20]
        derror  = resp[20,4].unpack("V")[0]

        # Catch access denied replies to OpenDomain
        if(derror != 0)
          next
        end

        # Password information
        stub = dhandle + [0x01].pack('v')
        dcerpc.call(8, stub)
        resp = dcerpc.last_response ? dcerpc.last_response.stub_data : nil
        if(resp and resp[-4,4].unpack('V')[0] == 0)
          mlen,hlen = resp[8,4].unpack('vv')
          domains[domain][:pass_min] = mlen
          domains[domain][:pass_min_history] = hlen
        end

        # Server Role
        stub = dhandle + [0x07].pack('v')
        dcerpc.call(8, stub)
        if(resp and resp[-4,4].unpack('V')[0] == 0)
          resp = dcerpc.last_response ? dcerpc.last_response.stub_data : nil
          domains[domain][:server_role] = resp[8,2].unpack('v')[0]
        end

        # Lockout Threshold
        stub = dhandle + [12].pack('v')
        dcerpc.call(8, stub)
        resp = dcerpc.last_response ? dcerpc.last_response.stub_data : nil

        if(resp and resp[-4,4].unpack('V')[0] == 0)
          lduration = resp[8,8]
          lwindow   = resp[16,8]
          lthresh   = resp[24, 2].unpack('v')[0]

          domains[domain][:lockout_threshold] = lthresh
          domains[domain][:lockout_duration]  = Rex::Proto::SMB::Utils.time_smb_to_unix(*(lduration.unpack('V2')))
          domains[domain][:lockout_window]    = Rex::Proto::SMB::Utils.time_smb_to_unix(*(lwindow.unpack('V2')))
        end

        # Users
        stub = dhandle + NDR.long(0) + NDR.long(0x10) + NDR.long(1024*1024)
        dcerpc.call(13, stub)
        resp  = dcerpc.last_response ? dcerpc.last_response.stub_data : nil
        if(resp and resp[-4,4].unpack('V')[0] == 0)
          domains[domain][:users] = smb_parse_sam_users(resp)
        end


        # Close Domain
        dcerpc.call(1, dhandle)
      end

      # Close Policy
      dcerpc.call(1, phandle)


      domains.each_key do |domain|

        # Delete the no longer used raw SID value
        domains[domain].delete(:sid_raw)

        # Store the domain name itself
        domains[domain][:name] = domain

        # Store the domain information
        report_note(
          :host => ip,
          :proto => 'tcp',
          :port => datastore['RPORT'],
          :type => 'smb.domain.enumusers',
          :data => domains[domain]
        )

        users = domains[domain][:users] || {}
        extra = ""
        if (domains[domain][:lockout_threshold])
          extra = "( "
          extra << "LockoutTries=#{domains[domain][:lockout_threshold]} "
          extra << "PasswordMin=#{domains[domain][:pass_min]} "
          extra << ")"
        end
        print_status("#{ip} #{domain.upcase} [ #{users.keys.map{|k| users[k]}.join(", ")} ] #{extra}")
      end

      # cleanup
      disconnect
      return
    rescue ::Timeout::Error
    rescue ::Interrupt
      raise $!
    rescue ::Rex::ConnectionError
    rescue ::Rex::Proto::SMB::Exceptions::LoginError
      next
    rescue ::Exception => e
      print_line("Error: #{ip} #{e.class} #{e}")
    end
    end
  end


end
