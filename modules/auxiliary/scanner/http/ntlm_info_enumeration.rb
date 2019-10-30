##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Host Information Enumeration via NTLM Authentication',
      'Description' => %q{
          This module makes requests to resources on the target server in
        an attempt to find resources which permit NTLM authentication. For
        resources which permit NTLM authentication, a blank NTLM type 1 message
        is sent to enumerate a type 2 message from the target server. The type
        2 message is then parsed for information such as the Active Directory
        domain and NetBIOS name.  A single URI can be specified with TARGET_URI
        and/or a file of URIs can be specified with TARGET_URIS_FILE (default).
      },
      'Author'      => 'Brandon Knight',
      'License'     => MSF_LICENSE
    )
    register_options(
      [
        OptString.new('TARGET_URI', [ false, "Single target URI", nil]),
        OptPath.new('TARGET_URIS_FILE', [ false, "Path to list of URIs to request",
          File.join(Msf::Config.data_directory, "wordlists", "http_owa_common.txt")]),
      ])
  end

  def run_host(ip)
    test_uris = []
    turi = datastore['TARGET_URI']
    turis_file = datastore['TARGET_URIS_FILE']
    if (!turi && !turis_file)
      # can't simply return here as we'll print an error for each host
      fail_with "Either TARGET_URI or TARGET_URIS_FILE must be specified"
    end
    if (turi && !turi.blank?)
      test_uris << normalize_uri(turi)
    end
    if (turis_file && !turis_file.blank?)
      File.open(turis_file, 'rb') { |f| test_uris += f.readlines }
      test_uris.collect! do |test_uri|
        normalize_uri(test_uri.chomp)
      end
    end
    test_uris.each do |test_path|
      result = check_url(test_path)
      # no need to try the other uris if one of them works.
      return handle_result(test_path, result) if result
    end
  end

  def handle_result(path, result)
    message = "Enumerated info on #{peer}#{path} - "
    message << "(name:#{result[:nb_name]}) "
    message << "(domain:#{result[:nb_domain]}) "
    message << "(domain_fqdn:#{result[:dns_domain]}) "
    message << "(server_fqdn:#{result[:dns_server]})"
    print_good(message)
    report_note(
      :host  => rhost,
      :port  => rport,
      :proto => 'tcp',
      :sname => (ssl ? 'https' : 'http'),
      :ntype => 'ntlm.enumeration.info',
      :data  => {
        :uri        => path,
        :SMBName    => result[:nb_name],
        :SMBDomain  => result[:nb_domain],
        :FQDNDomain => result[:dns_domain],
        :FQDNName   => result[:dns_server]
      },
      :update => :unique_data
    )
  end

  def check_url(test_uri)
    begin

      vprint_status("Checking #{peer} URL #{test_uri}")
      res = send_request_cgi({
        'encode'   => true,
        'uri'      => "#{test_uri}",
        'method'   => 'GET',
        'headers'  =>  { "Authorization" => "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=="}
      })
    rescue OpenSSL::SSL::SSLError
      vprint_error("SSL error")
      return
    rescue Errno::ENOPROTOOPT, Errno::ECONNRESET, ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::ArgumentError
      vprint_error("Unable to Connect")
      return
    rescue ::Timeout::Error, ::Errno::EPIPE
      vprint_error("Timeout error")
      return
    end

    return if res.nil?

    vprint_status("Status: #{res.code}")
    if res && res.code == 401 && res['WWW-Authenticate'] && res['WWW-Authenticate'].match(/^NTLM/i)
      hash = res['WWW-Authenticate'].split('NTLM ')[1]
      # Parse out the NTLM and just get the Target Information Data
      target = Rex::Proto::NTLM::Message.parse(Rex::Text.decode_base64(hash))[:target_info].value()
      # Retrieve Domain name subblock info
      nb_domain = parse_ntlm_info(target, "\x02\x00", 0)
      # Retrieve Server name subblock info
      nb_name = parse_ntlm_info(target, "\x01\x00", nb_domain[:new_offset])
      # Retrieve DNS domain name subblock info
      dns_domain = parse_ntlm_info(target, "\x04\x00", nb_name[:new_offset])
      # Retrieve DNS server name subblock info
      dns_server = parse_ntlm_info(target, "\x03\x00", dns_domain[:new_offset])

      return {
        :nb_name    => nb_name[:message],
        :nb_domain  => nb_domain[:message],
        :dns_domain => dns_domain[:message],
        :dns_server => dns_server[:message]
      }
    end
  end

  def parse_ntlm_info(message,pattern,offset)
    name_index = message.index(pattern,offset)
    offset = name_index.to_i
    size = message[offset+2].unpack('C').first
    return {
      :message=>message[offset+3,size].gsub(/\0/,''),
      :new_offset => offset + size
    }
  end
end
