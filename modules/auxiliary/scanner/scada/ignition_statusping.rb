# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Inductive Automation Ignition Gateway Fingerprint',
        'Description' => %q{
          Fingerprints Inductive Automation Ignition gateways across all major versions
          by probing version-specific unauthenticated info endpoints. Extracts version,
          run state, OS, Java runtime, and GAN redundancy role without authentication.

          Endpoint and response format by version:
          7.9.x  — /main/system/gwinfo  (semicolon-delimited key=value)
          8.0.x  — /system/gwinfo       (semicolon-delimited key=value)
          8.1.x  — /system/StatusPing   (JSON)
          8.3.x  — /system/gwinfo       (semicolon-delimited key=value, additional fields)

          For 8.0.x exploitation see exploit/multi/scada/inductive_ignition_rce.
        },
        'Author' => ['Ethan Thomason <ethan@ethomason.com>'],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://ethomason.com/posts/fingerprinting-ignition-gateways/'],
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )
    register_options([Opt::RPORT(8088)])
  end

  # Parse semicolon-delimited key=value format used by 7.9.x, 8.0.x, 8.3.x
  # e.g. ContextStatus=RUNNING;Version=8.3.4;OS=Linux;RuntimeVersion=17.0.17
  def parse_gwinfo(body)
    info = {}
    body.split(';').each do |pair|
      k, v = pair.split('=', 2)
      info[k.strip] = v.to_s.strip if k
    end
    info
  end

  # Parse JSON format used by 8.1.x StatusPing
  def parse_statusping(body)
    document = JSON.parse(body)
    return {} unless document.is_a?(Hash)

    %w[version state role peerAddress os runtimeVersion].each_with_object({}) do |key, info|
      info[key] = document[key] if document[key]
    end
  rescue JSON::ParserError
    {}
  end

  def build_info_string(version, state, os, runtime, role, peer)
    parts = ["Ignition #{version}"]
    parts << "State: #{state}" if state
    parts << "OS: #{os}" if os
    parts << "Java: #{runtime}" if runtime
    parts << "GAN role: #{role}" if role
    parts << "Peer: #{peer}" if peer && role && role !~ /independent/i
    parts.join(' | ')
  end

  def run_host(ip)
    probes = [
      { uri: '/system/gwinfo', format: :kvp },
      { uri: '/system/StatusPing', format: :json },
      { uri: '/main/system/gwinfo', format: :kvp },
    ]

    found = false

    probes.each do |probe|
      res = send_request_cgi({ 'method' => 'GET', 'uri' => probe[:uri] })
      next unless res && res.code == 200
      next if res.body.strip.empty?

      version = state = os = runtime = role = peer = nil

      if probe[:format] == :kvp
        d = parse_gwinfo(res.body)
        version = d['Version']
        state = d['ContextStatus']
        os = d['OS']
        runtime = d['RuntimeVersion']
        role = d['RedundancyStatus']
      elsif probe[:format] == :json
        # Skip the minimal 8.3.x StatusPing stub which returns only state
        next if res.body.strip == '{"state":"RUNNING"}'

        d = parse_statusping(res.body)
        version = d['version']
        state = d['state']
        os = d['os']
        runtime = d['runtimeVersion']
        role = d['role']
        peer = d['peerAddress']
      end

      next unless version

      info_str = build_info_string(version, state, os, runtime, role, peer)
      print_good("#{Rex::Socket.to_authority(ip, rport)} - #{info_str}")

      report_host(host: ip, os_name: os) if os
      report_note(
        host: ip,
        type: 'ignition.gateway',
        data: { version: version, state: state, role: role, runtime: runtime }
      )
      report_service(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: ssl ? 'https' : 'http',
        info: info_str
      )

      found = true
      break
    end

    vprint_status("#{Rex::Socket.to_authority(ip, rport)} - No Ignition endpoint responded") unless found
  end
end
