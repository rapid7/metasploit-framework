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
          in place, such as SMEP, SMAP, SELinux, PaX and grsecurity. It also
          tries to find installed applications that can be used to hinder,
          prevent, or detect attacks, such as tripwire, snort, and apparmor.

          This module is meant to identify Linux Secure Modules (LSM) in addition
          to various antivirus, IDS/IPS, firewalls, sandboxes and other security
          related software.
        },
        'License' => MSF_LICENSE,
        'Author' => 'ohdae <bindshell[at]live.com>',
        'Platform' => ['linux'],
        'SessionTypes' => ['shell', 'meterpreter']
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

  def report(data)
    report_note(
      host: session,
      type: 'linux.protection',
      data: data,
      update: :unique_data
    )
  end

  def check_hardening
    begin
      if aslr_enabled?
        r = 'ASLR is enabled'
        print_good r
        report r
      end
    rescue RuntimeError => e
      vprint_status("#{e}")
    end

    begin
      if exec_shield_enabled?
        r = 'Exec-Shield is enabled'
        print_good r
        report r
      end
    rescue RuntimeError => e
      vprint_status("#{e}")
    end

    begin
      if kaiser_enabled?
        r = 'KAISER is enabled'
        print_good r
        report r
      end
    rescue RuntimeError => e
      vprint_status("#{e}")
    end

    begin
      if smep_enabled?
        r = 'SMEP is enabled'
        print_good r
        report r
      end
    rescue RuntimeError => e
      vprint_status("#{e}")
    end

    begin
      if smap_enabled?
        r = 'SMAP is enabled'
        print_good r
        report r
      end
    rescue RuntimeError => e
      vprint_status("#{e}")
    end

    begin
      if lkrg_installed?
        r = 'LKRG is installed'
        print_good r
        report r
      end
    rescue RuntimeError => e
      vprint_status("#{e}")
    end

    begin
      if grsec_installed?
        r = 'grsecurity is installed'
        print_good r
        report r
      end
    rescue RuntimeError => e
      vprint_status("#{e}")
    end

    begin
      if pax_installed?
        r = 'PaX is installed'
        print_good r
        report r
      end
    rescue RuntimeError => e
      vprint_status("#{e}")
    end

    begin
      if selinux_installed?
        if selinux_enforcing?
          r = 'SELinux is installed and enforcing'
        else
          r = 'SELinux is installed, but in permissive mode'
        end
        print_good r
        report r
      end
    rescue RuntimeError => e
      vprint_status("#{e}")
    end

    begin
      if yama_installed?
        if yama_enabled?
          r = 'Yama is installed and enabled'
        else
          r = 'Yama is installed, but not enabled'
        end
        print_good r
        report r
      end
    rescue RuntimeError => e
      vprint_status("#{e}")
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
      'elastic-agent' => 'Elastic Security',
      'firejail' => 'Firejail',
      'firestarter' => 'Firestarted',
      'fw-settings' => 'Uncomplicated FireWall (UFW)',
      'getenforce' => 'SELinux',
      'gradm' => 'grsecurity',
      'gradm2' => 'grsecurity',
      'honeyd' => 'Honeyd',
      'iptables' => 'iptables',
      'jailkit' => 'jailkit',
      'logrotate' => 'logrotate',
      'logwatch' => 'logwatch',
      'lynis' => 'lynis',
      'nagios' => 'nagios',
      'oz-seccomp' => 'OZ',
      'paxctl' => 'PaX',
      'paxctld' => 'PaX',
      'paxtest' => 'PaX',
      'proxychains' => 'ProxyChains',
      'psad' => 'psad',
      'rkhunter' => 'rkhunter',
      'snort' => 'snort',
      'tcpdump' => 'tcpdump',
      'thpot' => 'thpot',
      'tiger' => 'tiger',
      'tripwire' => 'tripwire',
      'ufw' => 'Uncomplicated FireWall (UFW)',
      'wireshark' => 'Wireshark'
    }

    apps.each do |app, appname|
      next unless command_exists? app

      path = cmd_exec "command -v #{app}"
      next unless path.start_with? '/'

      print_good "#{app} found: #{path}"
      report "#{appname}: #{path}"
    end
  end

  def find_config
    apps = {
      '/bin/logrhythm' => 'LogRhythm Axon',
      '/etc/aide/aide.conf' => 'Advanced Intrusion Detection Environment (AIDE)',
      '/etc/chkrootkit' => 'chkrootkit [chkrootkit -q]',
      '/etc/clamd.d/scan.conf' => 'ClamAV',
      '/etc/fluent-bit' => 'Fluent Bit Log Collector',
      '/etc/freshclam.conf' => 'ClamAV',
      '/etc/init.d/avast' => 'Avast',
      '/etc/init.d/avgd' => 'AVG',
      '/etc/init.d/ds_agent' => 'Trend Micro Deep Instinct',
      '/etc/init.d/fortisiem-linux-agent' => 'Fortinet FortiSIEM',
      '/etc/init.d/kics' => 'Kaspersky Industrial CyberSecurity',
      '/etc/init.d/limacharlie' => 'LimaCharlie Agent',
      '/etc/init.d/qualys-cloud-agent' => 'Qualys EDR Cloud Agent',
      '/etc/init.d/scsm' => 'LogRhythm System Monitor',
      '/etc/init.d/sisamdagent' => 'Symantec EDR',
      '/etc/init.d/splx' => 'Trend Micro Server Protect',
      '/etc/init.d/threatconnect-envsvr' => 'ThreatConnect',
      '/etc/logrhythm' => 'LogRhythm Axon',
      '/etc/opt/f-secure' => 'WithSecure (F-Secure)',
      '/etc/otelcol-sumo/sumologic.yaml' => 'Sumo Logic OTEL Collector',
      '/etc/rkhunter.conf' => 'rkhunter',
      '/etc/safedog/sdsvrd.conf' => 'Safedog',
      '/etc/safedog/server/conf/sdsvrd.conf' => 'Safedog',
      '/etc/tripwire' => 'TripWire',
      '/opt/COMODO' => 'Comodo AV',
      '/opt/CrowdStrike' => 'CrowdShite',
      '/opt/FortiEDRCollector' => 'Fortinet FortiEDR',
      '/opt/FortiEDRCollector/scripts/fortiedrconfig.sh' => 'Fortinet FortiEDR',
      '/opt/McAfee' => 'FireEye/McAfee/Trellix Agent',
      '/opt/SumoCollector' => 'Sumo Logic Cloud SIEM',
      '/opt/Symantec' => 'Symantec EDR',
      '/opt/Tanium' => 'Tanium',
      '/opt/Trellix' => 'FireEye/McAfee/Trellix SIEM Collector',
      '/opt/avg' => 'AVG',
      '/opt/bitdefender-security-tools/bin/bdconfigure' => 'Bitdefender EDR',
      '/opt/cisco/amp/bin/ampcli ' => 'Cisco Secure Endpoint',
      '/opt/cisco/amp/bin/ampcli' => 'Cisco Secure Endpoint',
      '/opt/cyberark' => 'CyberArk',
      '/opt/ds_agent/dsa' => 'Trend Micro Deep Security Agent',
      '/opt/f-secure' => 'WithSecure (F-Secure)',
      '/opt/fireeye' => 'FireEye/Trellix EDR',
      '/opt/fortinet/fortisiem' => 'Fortinet FortiSIEM',
      '/opt/isec' => 'FireEye/Trellix Endpoint Security',
      '/opt/kaspersky' => 'Kaspersky',
      '/opt/logrhythm/scsm' => 'LogRhythm System Monitor',
      '/opt/secureworks' => 'Secureworks',
      '/opt/sentinelone/bin/sentinelctl' => 'SentinelOne',
      '/opt/splunkforwarder' => 'Splunk',
      '/opt/threatbook/OneAV' => 'threatbook.OneAV',
      '/opt/threatconnect-envsvr/' => 'ThreatConnect',
      '/opt/traps/bin/cytool' => 'Palo Alto Networks Cortex XDR',
      '/sf/edr/agent/bin/edr_agent' => 'Sangfor EDR',
      '/titan/agent/agent_update.sh' => 'Titan Agent',
      '/usr/bin/linep' => 'Group-iB XDR Endpoint Agent',
      '/usr/bin/oneav_start' => 'threatbook.OneAV',
      '/usr/lib/Acronis' => 'Acronis Cyber Protect',
      '/usr/lib/symantec/status.sh' => 'Symantec Linux Agent',
      '/usr/local/bin/intezer-analyze' => 'Intezer',
      '/usr/local/qualys' => 'Qualys EDR Cloud Agent',
      '/usr/local/rocketcyber' => 'Kseya RocketCyber',
      '/var/lib/avast/Setup/avast.vpsupdate' => 'Avast',
      '/var/log/checkpoint' => 'Checkpoint',
      '/var/pt' => 'PT Swarm'
    }

    apps.each do |path, appname|
      next unless file_exist?(path) || directory?(path)

      print_good "#{appname} found: #{path}"
      report "#{appname}: #{path}"
    rescue RuntimeError
      print_bad("Unable to determine state of #{appname}")
      next
    end
  end
end
