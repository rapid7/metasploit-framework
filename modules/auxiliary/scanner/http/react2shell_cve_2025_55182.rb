##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Pre-Auth RCE in React and Next.js Scanner',
        'Description' => %q{
          This module checks for the presence of a Pre-Auth RCE vulnerability in React Server Components.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Maksim Rogov', # Metasploit Module
          'Lachlan Davidson', # Vulnerability Discovery
          'Adam Kues', # Detection Mechanism
        ],
        'References' => [
          ['CVE', '2025-55182'],
          ['CVE', '2025-66478'],
          ['URL', 'https://slcyber.io/research-center/high-fidelity-detection-mechanism-for-rsc-next-js-rce-cve-2025-55182-cve-2025-66478/']
        ],
        'Platform' => ['linux'],
        'DisclosureDate' => '2025-12-03',
        'Notes' => {
          'Stability' => [],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'Path to the React App', '/']),
      ]
    )
  end

  def target_url
    normalize_uri(datastore['URI'])
    "http://#{vhost}:#{rport}#{datastore['URI']}"
  end

  def run_host(_ip)
    post_data = Rex::MIME::Message.new
    post_data.add_part('{}', nil, nil, 'form-data; name="1"')
    post_data.add_part('["$1::"]', nil, nil, 'form-data; name="0"')

    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path),
      'method' => 'POST',
      'headers' => { 'Next-Action' => '' },
      'ctype' => "multipart/form-data; boundary=#{post_data.bound}",
      'data' => post_data.to_s
    )
    fail_with(Failure::Unreachable, "#{peer} - No response from web service") unless res

    resp_text = res.get_html_document.text
    return print_good("The target #{target_url} appears to be vulnerable") if res.code == 500 && resp_text.include?('E{"digest":"')

    return print_error("The target #{target_url} is not vulnerable")
  end
end
