##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Module name',
      'Description'    => %q{
         This module enables an authenticated user to view the usernames and encrypted passwords of other users in the Dolibarr ERP/CRM via SQL injection.
      },
      'Author'         => [ 'Issam Rabhi' ],  # PoC
                          [ 'Kevin Locati' ], # PoC
                          [ 'Shelby Pace' ]   # Metasploit Module
      'License'        => MSF_LICENSE,
      'References'     => [
                            [ 'CVE', '2018-10094' ],
                            [ 'EDB', '44805']
                          ]
    ))

    register_options(
      OptString.new('USERNAME', [ true, 'The username for authenticating to Dolibarr', 'admin' ])
      OptString.new('PASSWORD', [ true, 'The password for authenticating to Dolibarr', 'admin' ])
    )
  end

  def login

  end

  def get_info

  end

  def run

  end
end
