# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Kernel
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Linux Gather Protection Enumeration',
        'Description' => %q{
          This module checks whether popular system hardening mechanisms are
          in place, such as SMEP, SMAP, KPTI, SELinux, PaX, grsecurity, and
          Yama. It also tries to find installed applications that can be used
          to hinder, prevent, or detect attacks, such as tripwire, snort,
          apparmor, falco, and wazuh.

          This module is meant to identify Linux Secure Modules (LSM) in addition
          to various antivirus, IDS/IPS, firewalls, sandboxes and other security
          related software.
        },
        'License' => MSF_LICENSE,
        'Author' => 'ohdae <bindshell[at]live.com>',
        'Platform' => ['linux'],
        'SessionTypes' => ['shell', 'meterpreter'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
  end

  def run
    distro = get_sysinfo

    print_status "Running module against #{session.session_host} [#{get_hostname}]"
    print_status 'Info:'
    print_status "\t#{distro[:version]}"
    print_status "\t#{distro[:kernel]}"

    print_status 'Finding system protections...'
    check_hardening

    print_status 'Finding installed applications via their executables...'
    find_exes

    print_status 'Finding installed applications via their configuration files...'
    find_config

    if framework.db.active
      print_status 'System protections saved to notes.'
    end
  end

  def report(**data)
    report_note(
      host: session,
      type: 'linux.protection',
      data: data,
      update: :unique_data
    )
  end

  def check_hardening
    hardening_checks = {
      aslr_enabled?: 'ASLR is enabled',
      exec_shield_enabled?: 'Exec-Shield is enabled',
      kaiser_enabled?: 'KAISER is enabled',
      kpti_enabled?: 'KPTI is enabled',
      smep_enabled?: 'SMEP is enabled',
      smap_enabled?: 'SMAP is enabled',
      lkrg_installed?: 'LKRG is installed',
      grsec_installed?: 'grsecurity is installed',
      pax_installed?: 'PaX is installed',
      unprivileged_bpf_disabled?: 'Unprivileged BPF is disabled',
      kptr_restrict?: 'Kernel pointer restriction is enabled',
      dmesg_restrict?: 'dmesg restriction is enabled'
    }

    hardening_checks.each do |check, message|
      if send(check)
        print_good message
        report(message: message)
      end
    rescue RuntimeError => e
      vprint_status(e.to_s)
    end

    # SELinux has additional enforcing/permissive state
    begin
      if selinux_installed?
        r = if selinux_enforcing?
              'SELinux is installed and enforcing'
            else
              'SELinux is installed, but in permissive mode'
            end
        print_good(r)
        report(message: r)
      end
    rescue RuntimeError => e
      vprint_status(e.to_s)
    end

    # Yama has additional enabled/disabled state
    begin
      if yama_installed?
        r = if yama_enabled?
              'Yama is installed and enabled'
            else
              'Yama is installed, but not enabled'
            end
        print_good(r)
        report(message: r)
      end
    rescue RuntimeError => e
      vprint_status(e.to_s)
    end

    # User namespaces - report as an attack surface when enabled
    begin
      if userns_enabled?
        r = 'User namespaces are enabled (unprivileged may be available)'
        print_good(r)
        report(message: r)
      end
    rescue RuntimeError => e
      vprint_status(e.to_s)
    end
  end

  def find_exes
    apps = {
      'aa-status' => 'AppArmor',
      'aide' => 'Advanced Intrusion Detection Environment (AIDE)',
      'apparmor' => 'AppArmor',
      'auditd' => 'auditd',
      'avast' => 'Avast',
      'bastille' => 'Bastille',
      'bulldog' => 'Bulldog',
      'chkrootkit' => 'chkrootkit',
      'clamav' => 'ClamAV',
      'cylance' => 'Arctic Wolf Aurora Endpoint Security (formerly Cylance PROTECT)',
      'elastic-agent' => 'Elastic Security',
      'fail2ban-client' => 'fail2ban',
      'falco' => 'Falco Runtime Security',
      'firewall-cmd' => 'firewalld',      
      'firejail' => 'Firejail',
      'firestarter' => 'Firestarter',
      'fw-settings' => 'Uncomplicated FireWall (UFW)',
      'getenforce' => 'SELinux',
      'gradm' => 'grsecurity',
      'gradm2' => 'grsecurity',
      'honeyd' => 'Honeyd',
      'hurukai' => 'HarfangLab EDR',
      'intezer-cli' => 'Intezer',
      'intezer_linux_endpoint_scanner.sh' => 'Intezer',
      'iptables' => 'iptables',
      'jailkit' => 'jailkit',
      'logrotate' => 'logrotate',
      'logwatch' => 'logwatch',
      'lynis' => 'lynis',
      'mdatp' => 'MS Defender',
      'nagios' => 'nagios',
      'nft' => 'nftables',
      'nsclient' => 'Netskope Client',
      'nwe-agent' => 'NetWitness Endpoint (RSA)',
      'opensnitch' => 'OpenSnitch',
      'opswat-gears-od' => 'OPSWAT MetaDefender',
      'osqueryi' => 'osquery',
      'ossec-control' => 'OSSEC HIDS',
      'osqueryd' => 'osquery',
      'oz-seccomp' => 'OZ',
      'paxctl' => 'PaX',
      'paxctld' => 'PaX',
      'paxtest' => 'PaX',
      'proxychains' => 'ProxyChains',
      'psad' => 'psad',
      'rkhunter' => 'rkhunter',
      'siggen' => 'Tripwire (Open Source)',
      'snort' => 'snort',
      'suricata' => 'Suricata IDS/IPS',
      'sysdig' => 'Sysdig',
      'sysmon' => 'Sysmon for Linux',
      'tcpdump' => 'tcpdump',
      'thpot' => 'thpot',
      'threatlockerctl' => 'ThreatLocker',
      'tiger' => 'tiger',
      'tracee' => 'Tracee (Aqua)',
      'tripwire' => 'tripwire',
      'twadmin' => 'Tripwire (Open Source)',
      'twprint' => 'Tripwire (Open Source)',
      'ufw' => 'Uncomplicated FireWall (UFW)',
      'wazuh-control' => 'Wazuh',
      'wireshark' => 'Wireshark',
      'zeek' => 'Zeek Network Monitor'
    }

    apps.each do |app, appname|
      next unless command_exists? app

      path = cmd_exec "command -v #{app}"
      next unless path.start_with? '/'

      print_good("#{app} found: #{path}")
      report(message: "Found: #{appname}", path: path)
    end
  end

  def find_config
    apps = {
      '/bin/logrhythm' => 'LogRhythm Axon',
      '/dgagent/dgctl' => 'Fortra Digital Guardian (formerly Verdasys)',
      '/etc/aide/aide.conf' => 'Advanced Intrusion Detection Environment (AIDE)',
      '/etc/centrifydc' => 'Delinea / Centrify Server Suite',
      '/etc/chkrootkit' => 'chkrootkit',
      '/etc/clamd.d/scan.conf' => 'ClamAV',
      '/etc/environment.d/binalyze-air-agent.conf' => 'Binalyze AIR',
      '/etc/fail2ban' => 'fail2ban',
      '/etc/falco' => 'Falco Runtime Security',
      '/etc/filebeat' => 'Filebeat (not AV/EDR, but used to ship logs)',
      '/etc/firewalld' => 'firewalld',
      '/etc/fleetspeak-client' => 'GRR Rapid Response',
      '/etc/fluent-bit' => 'Fluent Bit Log Collector',
      '/etc/freshclam.conf' => 'ClamAV',
      '/etc/init.d/avast' => 'Avast',
      '/etc/init.d/avgd' => 'AVG',
      '/etc/init.d/cma' => 'Trellix ENS Agent (formerly McAfee)',
      '/etc/init.d/ds_agent' => 'Trend Micro Deep Instinct',
      '/etc/init.d/fortisiem-linux-agent' => 'Fortinet FortiSIEM',
      '/etc/init.d/kess' => 'Kaspersky Embedded Systems Security',
      '/etc/init.d/kics' => 'Kaspersky Industrial CyberSecurity',
      '/etc/init.d/limacharlie' => 'LimaCharlie Agent',
      '/etc/init.d/ossec' => 'OSSEC',
      '/etc/init.d/qualys-cloud-agent' => 'Qualys EDR Cloud Agent',
      '/etc/init.d/scsm' => 'LogRhythm System Monitor',
      '/etc/init.d/sisamdagent' => 'Symantec EDR',
      '/etc/init.d/splx' => 'Trend Micro Server Protect',
      '/etc/init.d/threatconnect-envsvr' => 'ThreatConnect',
      '/etc/logrhythm' => 'LogRhythm Axon',
      '/etc/nftables.conf' => 'nftables',
      '/etc/opt/f-secure' => 'WithSecure (F-Secure)',
      '/etc/osquery' => 'osquery',
      '/etc/otelcol-sumo/sumologic.yaml' => 'Sumo Logic OTEL Collector',
      '/etc/opensnitchd' => 'OpenSnitch',
      '/etc/rc.d/init.d/ossec' => 'OSSEC',
      '/etc/reaqtahive.d' => 'IBM QRadar EDR (formerly ReaQta)',
      '/etc/rkhunter.conf' => 'rkhunter',
      '/etc/safedog/sdsvrd.conf' => 'Safedog',
      '/etc/safedog/server/conf/sdsvrd.conf' => 'Safedog',
      '/etc/sftd' => 'Okta Advanced Server Access / Privileged Access (sftd)',
      '/etc/suricata' => 'Suricata IDS/IPS',
      '/etc/syslog-ng/syslog-ng.conf' => 'syslog-ng (One Identity)',
      '/etc/teleport.yaml' => 'Teleport',
      '/etc/tetragon' => 'Tetragon (Isovalent/Cilium)',
      '/etc/tripwire' => 'TripWire',
      '/etc/velociraptor' => 'Velociraptor',
      '/opt/COMODO' => 'Comodo AV',
      '/opt/CrowdStrike' => 'CrowdStrike',
      '/opt/FortiEDRCollector' => 'Fortinet FortiEDR',
      '/opt/GC_Ext' => 'Microsoft Azure Arc (Connected Machine agent)',
      '/opt/GC_Service' => 'Microsoft Azure Arc (Connected Machine agent)',
      '/opt/McAfee' => 'FireEye/McAfee/Trellix Agent',
      '/opt/NinjaRMMAgent' => 'NinjaOne',
      '/opt/SentinelOne/bin/sentinelctl' => 'SentinelOne',
      '/opt/SumoCollector' => 'Sumo Logic Cloud SIEM',
      '/opt/Symantec' => 'Symantec EDR',
      '/opt/Tanium' => 'Tanium',
      '/opt/Trellix' => 'FireEye/McAfee/Trellix SIEM Collector',
      '/opt/amagent' => 'Automox',
      '/opt/aquasec' => 'Aqua Security Enforcer',
      '/opt/arcsight/connectors' => 'OpenText ArcSight SmartConnector',
      '/opt/avg' => 'AVG',
      '/opt/azcmagent/bin/azcmagent' => 'Microsoft Azure Arc (Connected Machine agent)',
      '/opt/binalyze/air/agent/air' => 'Binalyze AIR',
      '/opt/bitdefender-security-tools/bin/bdconfigure' => 'Bitdefender EDR',
      '/opt/centrify/bin/adclient' => 'Delinea / Centrify Server Suite',
      '/opt/cisco/amp/bin/ampcli' => 'Cisco Secure Endpoint',
      '/opt/cribl-edge' => 'Cribl Edge',
      '/opt/cyberark' => 'CyberArk',
      '/opt/cylance/desktop/cylance' => 'Arctic Wolf Aurora Endpoint Security (formerly Cylance PROTECT)',
      '/opt/datadog-agent' => 'Datadog Agent (Cloud Security Management / CWS)',
      '/opt/draios' => 'Sysdig Secure agent',
      '/opt/drweb.com' => 'Dr.Web for Linux',
      '/opt/ds_agent/dsa' => 'Trend Micro Deep Security Agent',
      '/opt/f-secure' => 'WithSecure (F-Secure)',
      '/opt/fireeye' => 'FireEye/Trellix EDR',
      '/opt/fortinet/fortisiem' => 'Fortinet FortiSIEM',
      '/opt/isec' => 'FireEye/Trellix Endpoint Security',
      '/opt/jc' => 'JumpCloud agent',
      '/opt/kaspersky' => 'Kaspersky',
      '/opt/logrhythm/scsm' => 'LogRhythm System Monitor',
      '/opt/nessus_agent' => 'Tenable Nessus Agent',
      '/opt/netskope/stagent' => 'Netskope Client',
      '/opt/nxlog' => 'NXLog',
      '/opt/observiq-otel-collector' => 'Google SecOps / Chronicle BindPlane agent',
      '/opt/orbit' => 'Fleet (fleetd / Orbit - osquery manager)',
      '/opt/osquery' => 'osquery',
      '/opt/panda-security/endpoint' => 'WatchGuard EDR / EPDR (formerly Panda Adaptive Defense 360)',
      '/opt/pbul' => 'BeyondTrust Privilege Management for Unix & Linux (PMUL)',
      '/opt/secureworks' => 'Secureworks',
      '/opt/sentinelone/bin/sentinelctl' => 'SentinelOne',
      '/opt/splunkforwarder' => 'Splunk',
      '/opt/sysmon' => 'Sysmon for Linux',
      '/opt/threatbook/OneAV' => 'threatbook.OneAV',
      '/opt/threatconnect-envsvr/' => 'ThreatConnect',
      '/opt/traps/bin/cytool' => 'Palo Alto Networks Cortex XDR',
      '/opt/twistlock/fsmon' => 'Prisma Cloud Compute Defender (formerly Twistlock)',
      '/opt/wazuh' => 'Wazuh',
      '/opt/wiz/sensor' => 'Wiz runtime sensor',
      '/opt/zscaler' => 'Zscaler Client Connector',
      '/sf/edr/agent/bin/edr_agent' => 'Sangfor EDR',
      '/titan/agent/agent_update.sh' => 'Titan Agent',
      '/usr/bin/graylog-sidecar' => 'Graylog Sidecar',
      '/usr/bin/linep' => 'Group-iB XDR Endpoint Agent',
      '/usr/bin/oneav_start' => 'threatbook.OneAV',
      '/usr/bin/secureworks/taegis-ngav' => 'Secureworks NGAV',
      '/usr/bin/warp-cli' => 'Cloudflare WARP / Zero Trust',
      '/usr/lib/Acronis' => 'Acronis Cyber Protect',
      '/usr/lib/Seqrite/Seqrite' => 'Seqrite Endpoint Security (Quick Heal)',
      '/usr/lib/grr' => 'GRR Rapid Response',
      '/usr/lib/symantec/status.sh' => 'Symantec Linux Agent',
      '/usr/local/bin/intezer-analyze' => 'Intezer',
      '/usr/local/bin/teleport' => 'Teleport',
      '/usr/local/bin/tetra' => 'Tetragon (Isovalent/Cilium)',
      '/usr/local/bin/tetragon' => 'Tetragon (Isovalent/Cilium)',
      '/usr/local/bin/velociraptor_client' => 'Velociraptor',
      '/usr/local/qualys' => 'Qualys EDR Cloud Agent',
      '/usr/local/rocketcyber' => 'Kaseya RocketCyber',
      '/usr/local/tripwire/te/agent' => 'Tripwire Enterprise Agent',
      '/usr/sbin/SnareDispatchHelper' => 'Snare Enterprise Agent (Prophecy International)',
      '/usr/sbin/pbmasterd' => 'BeyondTrust Privilege Management for Unix & Linux (PMUL)',
      '/usr/share/huntress' => 'Huntress',
      '/var/lib/aquasec' => 'Aqua Security Enforcer',
      '/var/lib/avast/Setup/avast.vpsupdate' => 'Avast',
      '/var/lib/lacework/config/config.json' => 'Lacework (now Fortinet FortiCNAPP)',
      '/var/lib/twistlock' => 'Prisma Cloud Compute Defender (formerly Twistlock)',
      '/var/log/checkpoint' => 'Checkpoint',
      '/var/ossec' => 'OSSEC/Wazuh HIDS',
      '/var/pt' => 'PT Swarm'
    }

    apps.each do |path, appname|
      next unless file_exist?(path) || directory?(path)

      print_good("#{appname} found: #{path}")
      report(message: "#{appname}: #{path}")
    rescue RuntimeError
      print_bad("Unable to determine state of #{appname}")
      next
    end
  end
end
