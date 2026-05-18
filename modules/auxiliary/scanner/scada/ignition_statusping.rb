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
          by probing version-specific info endpoints. Extracts version, run state, OS,
          Java runtime, and GAN redundancy role without authentication.

          Endpoint and format by version:
          7.9.x  — /main/system/gwinfo  (key=value)
          8.0.x  — /system/gwinfo       (key=value)
          8.1.x  — /system/StatusPing   (JSON)
          8.3.x  — /system/gwinfo       (key=value, includes RuntimeVersion/RequireSsl)

          For 8.0.x exploitation see exploit/multi/scada/inductive_ignition_rce.
          For 8.1.x CVE modules see auxiliary/scanner/scada/ignition_auth_bypass and
          auxiliary/scanner/scada/ignition_deser_check.
        },
        'Author' => ['Ethan Thomason <ethan@cedartech.com>'],
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

  # Parse key=value format used by 7.9.x, 8.0.x, 8.3.x
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
    info = {}
    info['version'] = begin
      body.match(/"version"\s*:\s*"([^"]+)"/)[1]
    rescue StandardError
      nil
    end
    info['state'] = begin
      body.match(/"state"\s*:\s*"([^"]+)"/)[1]
    rescue StandardError
      nil
    end
    info['role'] = begin
      body.match(/"role"\s*:\s*"([^"]+)"/)[1]
    rescue StandardError
      nil
    end
    info['peerAddress'] = begin
      body.match(/"peerAddress"\s*:\s*"([^"]+)"/)[1]
    rescue StandardError
      nil
    end
    info['os'] = begin
      body.match(/"os"\s*:\s*"([^"]+)"/)[1]
    rescue StandardError
      nil
    end
    info.compact
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
    # Probe order: gwinfo covers 7.9/8.0/8.3, StatusPing covers 8.1
    probes = [
      { uri: '/system/gwinfo', format: :kvp },
      { uri: '/system/StatusPing', format: :json },
      { uri: '/main/system/gwinfo', format: :kvp },
    ]

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
        # gwinfo doesn't expose peer address directly
      elsif probe[:format] == :json
        # Skip if this is just the minimal 8.3.x StatusPing stub
        next if res.body.strip == '{"state":"RUNNING"}'

        d = parse_statusping(res.body)
        version = d['version']
        state = d['state']
        os = d['os']
        role = d['role']
        peer = d['peerAddress']
      end

      next unless version

      info_str = build_info_string(version, state, os, runtime, role, peer)
      print_good("#{ip}:#{rport} - #{info_str}")

      report_host(host: ip, os_name: 'Ignition Gateway', os_flavor: version)
      report_service(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: 'http',
        info: info_str
      )
      break # found it, don't probe further
    end

    vprint_status("#{ip}:#{rport} - No Ignition endpoint responded")
  end
end
