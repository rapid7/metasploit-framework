##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Kernel
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Linux Gather Protection Enumeration',
      'Description'   => %q{
        This module checks whether popular system hardening mechanisms are
        in place, such as SMEP, SMAP, SELinux, PaX and grsecurity. It also
        tries to find installed applications that can be used to hinder,
        prevent, or detect attacks, such as tripwire, snort, and apparmor.

        This module is meant to identify Linux Secure Modules (LSM) in addition
        to various antivirus, IDS/IPS, firewalls, sandboxes and other security
        related software.
      },
      'License'       => MSF_LICENSE,
      'Author'        => 'ohdae <bindshell[at]live.com>',
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell', 'meterpreter']
    ))
  end

  def run
    distro = get_sysinfo

    print_status "Running module against #{session.session_host} [#{get_hostname}]"
    print_status 'Info:'
    print_status "\t#{distro[:version]}"
    print_status "\t#{distro[:kernel]}"

    print_status 'Finding system protections...'
    check_hardening

    print_status 'Finding installed applications...'
    find_apps

    if framework.db.active
      print_status 'System protections saved to notes.'
    end
  end

  def report(data)
    report_note(
      :host   => session,
      :type   => 'linux.protection',
      :data   => data,
      :update => :unique_data
    )
  end

  def check_hardening
    if aslr_enabled?
      r = 'ASLR is enabled'
      print_good r
      report r
    end

    if exec_shield_enabled?
      r = 'Exec-Shield is enabled'
      print_good r
      report r
    end

    if kaiser_enabled?
      r = "KAISER is enabled"
      print_good r
      report r
    end

    if smep_enabled?
      r = "SMEP is enabled"
      print_good r
      report r
    end

    if smap_enabled?
      r = "SMAP is enabled"
      print_good r
      report r
    end

    if lkrg_installed?
      r = 'LKRG is installed'
      print_good r
      report r
    end

    if grsec_installed?
      r = 'grsecurity is installed'
      print_good r
      report r
    end

    if pax_installed?
      r = 'PaX is installed'
      print_good r
      report r
    end

    if selinux_installed?
      if selinux_enforcing?
        r = 'SELinux is installed and enforcing'
        print_good r
        report r
      else
        r = 'SELinux is installed, but in permissive mode'
        print_good r
        report r
      end
    end

    if yama_installed?
      if yama_enabled?
        r = 'Yama is installed and enabled'
        print_good r
        report r
      else
        r = 'Yama is installed, but not enabled'
        print_good r
        report r
      end
    end
  end

  def find_apps
    apps = %w(
      truecrypt bulldog ufw iptables fw-settings logrotate logwatch
      chkrootkit clamav snort tiger firestarter avast lynis
      rkhunter tcpdump webmin jailkit pwgen proxychains bastille
      psad wireshark nagios apparmor oz-seccomp honeyd thpot
      aa-status gradm gradm2 getenforce aide tripwire paxctl
    )

    apps.each do |app|
      next unless command_exists? app

      path = cmd_exec "command -v #{app}"
      next unless path.start_with? '/'

      print_good "#{app} found: #{path}"
      report path
    end
  end
end
