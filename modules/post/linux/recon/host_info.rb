# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework

class MetasploitModule < Msf::Post
  include Msf::Post::Linux::Kernel
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Update information about session host',
        'Description' => %q{
          Collects as much basic information on the current session as possible.
          Metherpreter sessions may do (most) of these functions automatically,
          but this module allows gathering even on basic shells in case a
          meterpreter session isnt viable.
          This is meant to help recon more data on a target or correct data assumed
          from external scans.
        },
        'License' => MSF_LICENSE,
        'Author' => ['Nick Cottrell <ncottrellweb[at]gmail.com>'],
        'Platform' => ['linux', 'unix', 'bsd'],
        'Privileged' => false,
        'SessionTypes' => %w[meterpreter shell],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => []
        }
      )
    )
    register_options([
      OptBool.new('RECON_HOSTNAME', [false, 'Report current sessions true hostname', true]),
      OptBool.new('RECON_ADDRESS', [false, 'Reports true address mac and interface', true]),
      OptBool.new('RECON_ARCH', [false, 'Reports systems true architecture', true]),
      OptBool.new('RECON_OS', [false, 'Reports true data on OS', true]),
      OptBool.new('RECON_SESSION_USER', [false, 'Reports the current user used for given session', true])
    ])
  end

  def run
    if datastore['RECON_HOSTNAME']
      print_good("Hostname is #{get_hostname}")
    end
    if datastore['RECON_ADDRESS']
      interface = nil
      mac = nil
      if session.type == 'meterpreter'
        session.net.config.each_interface do |iface|
          if iface.addrs.include?(session.session_host)
            interface = iface.mac_name.strip
            mac = iface.mac_addr.unpack('H*').first.gsub(/([\da-f]{2})/, '\1:').delete_suffix(':')
          end
        end
      end
      if interface.blank?
        ip_range = session.session_host[/^\d{,3}\.\d{,3}\.\d{,3}\./]
        interface = read_file('/proc/net/arp').scan(/^#{ip_range}\d{,3}\s+0x\d+\s+0x\d+\s+(?:[\da-f]{2}:){5}[\da-f]{2}\s+.+\s+([\w\d]+)$/).first
        interface = interface[0] if interface.any?
      end
      if mac.blank? && !interface.nil?
        mac = read_file("/sys/class/net/#{interface}/address")&.strip
      end
      print_good("The session is running on address #{session.session_host} (#{mac}) on interface #{interface}")
      report_host(host: session.session_host, mac: mac) if active_db?
    end
    if datastore['RECON_ARCH']
      host_arch = kernel_arch
      print_good("The hosts architecture is #{host_arch}")
      report_host(host: session.session_host, arch: host_arch) if active_db?
    end
    if datastore['RECON_OS']
      data = get_sysinfo
      print_good("The host is running #{data[:distro]} linux")
      print_good("version #{data[:version]}")
      print_good("running kernel #{data[:kernel]}")
    end
    if datastore['RECON_SESSION_USER']
      username = whoami
      credential_data = {
        origin_type: :session,
        post_reference_name: refname,
        session_id: session_db_id,
        username: username,
        workspace_id: myworkspace_id
      }
      print_good("The user running on the session is #{username}")
      create_credential(credential_data) if active_db? && !is_root?
    end
  end
end
