# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # Vulnerable: 0.8.3 <= version < 0.14.1 (fixed in 0.14.1).
  AFFECTED_MIN = '0.8.3'
  FIXED_IN = '0.14.1'

  # PIL's UnidentifiedImageError repr embeds the BytesIO object's heap address.
  # Vulnerable builds echo it verbatim; the fix (sanitize_message) collapses it to
  # "<_io.BytesIO object>" with no address.
  LEAK_RE = /<_io\.BytesIO object at 0x[0-9a-fA-F]+>/.freeze
  SANITIZED_RE = /<_io\.BytesIO object>/.freeze
  NO_IMAGE_RE = /does not support image input|image input is not supported|not a multimodal|no.*multimodal/i.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'vLLM Multimodal Heap-Address Information Leak Scanner',
        'Description' => %q{
          This module detects vLLM OpenAI-compatible servers affected by
          CVE-2026-22778. When an invalid image is sent to a multimodal endpoint,
          Pillow (PIL) raises UnidentifiedImageError whose message includes the
          Python repr of the underlying BytesIO buffer
          ("<_io.BytesIO object at 0x...>"), exposing a live heap address.
          Vulnerable versions return that error message directly to the client,
          which weakens ASLR and forms the first stage of a chain that ends in a
          JPEG2000 heap overflow in the bundled FFmpeg/OpenCV video decoder.
          Affected versions are 0.8.3 through 0.14.0 (fixed in 0.14.1, which
          sanitizes the address out of the message).

          The module first reads the unauthenticated /version banner and compares
          it against the affected range. It then issues a single benign request to
          the chat completions endpoint containing a deliberately malformed
          base64 image. If the response leaks a "0x" heap address the target is
          reported vulnerable with high confidence; if the address is stripped the
          fix is present; if the server reports that the model has no image support
          the leak path is not reachable as deployed. The probe never sends a
          video URL and never reaches the heap-overflow code path.
        },
        'Author' => [
          'Kenneth LaCroix' # Metasploit module
        ],
        'References' => [
          ['CVE', '2026-22778'],
          ['GHSA', '4r2x-xpjr-7cvv'],
          ['URL', 'https://orca.security/resources/blog/cve-2026-22778-vllm-rce-vulnerability/']
        ],
        'DisclosureDate' => '2026-02-02',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        },
        'DefaultOptions' => { 'RPORT' => 8000, 'SSL' => false }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'Base path to the vLLM OpenAI-compatible API', '/']),
        OptString.new('MODEL', [false, 'Model name for the probe (auto-detected from /v1/models when empty)', ''])
      ]
    )
  end

  # Reads the vLLM /version banner. Returns the version string or nil.
  def detect_version
    res = send_request_cgi('method' => 'GET', 'uri' => normalize_uri(target_uri.path, 'version'))
    return nil unless res&.code == 200

    body = res.get_json_document
    body.is_a?(Hash) ? body['version'] : nil
  end

  # Returns the served model id (MODEL option override, else first /v1/models entry).
  def detect_model
    return datastore['MODEL'] unless datastore['MODEL'].to_s.empty?

    res = send_request_cgi('method' => 'GET', 'uri' => normalize_uri(target_uri.path, 'v1', 'models'))
    return nil unless res&.code == 200

    data = res.get_json_document&.dig('data')
    return nil unless data.is_a?(Array) && data.first.is_a?(Hash)

    data.first['id']
  end

  # Sends one malformed image to the chat completions endpoint. Returns :leak,
  # :sanitized, :no_image, :no_model, or nil.
  def probe_image_leak(model)
    return :no_model unless model

    body = {
      'model' => model,
      'messages' => [
        {
          'role' => 'user',
          'content' => [
            { 'type' => 'text', 'text' => 'x' },
            { 'type' => 'image_url', 'image_url' => { 'url' => 'data:image/png;base64,bm90YW5pbWFnZQ==' } }
          ]
        }
      ],
      'max_tokens' => 1
    }.to_json

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'v1', 'chat', 'completions'),
      'ctype' => 'application/json',
      'data' => body
    )
    return nil unless res

    msg = res.body.to_s
    return :leak if msg =~ LEAK_RE
    return :sanitized if msg =~ SANITIZED_RE
    return :no_image if msg =~ NO_IMAGE_RE

    nil
  end

  def version_in_range?(ver)
    num = ver.to_s[/\d+\.\d+(?:\.\d+)?/]
    return false unless num

    v = Rex::Version.new(num)
    v >= Rex::Version.new(AFFECTED_MIN) && v < Rex::Version.new(FIXED_IN)
  end

  def check_host(_ip)
    ver = detect_version
    leak = probe_image_leak(detect_model)
    tag = ver ? " (vLLM #{ver})" : ''

    # Active behaviour is authoritative when we get a definitive signal.
    case leak
    when :leak
      return Exploit::CheckCode::Vulnerable("Heap-address leak confirmed via malformed image#{tag}")
    when :sanitized
      return Exploit::CheckCode::Safe("Error message sanitized; CVE-2026-22778 fix present#{tag}")
    end

    return Exploit::CheckCode::Unknown('No vLLM /version banner and no leak signal') unless ver

    unless version_in_range?(ver)
      return Exploit::CheckCode::Safe("vLLM #{ver} is outside the affected range (#{AFFECTED_MIN} <= v < #{FIXED_IN})")
    end

    detail = case leak
             when :no_image then 'no multimodal model loaded, leak path not reachable as deployed'
             when :no_model then 'no model advertised on /v1/models'
             else 'could not run active probe'
             end
    Exploit::CheckCode::Appears("vLLM #{ver} is in the affected range; #{detail}")
  end

  def run_host(ip)
    code = check_host(ip)

    if code == Exploit::CheckCode::Vulnerable
      print_good("#{peer} - #{code.reason}")
    elsif code == Exploit::CheckCode::Appears
      print_warning("#{peer} - #{code.reason}")
    else
      print_status("#{peer} - #{code.reason}")
      return
    end

    report_vuln(
      host: rhost,
      port: rport,
      name: name,
      info: code.reason,
      refs: references
    )
  end
end
