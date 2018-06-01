##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Pepa

  def initialize
    super(
      'Name'         => 'PEPA Whoami (whoami without whoami)',
      'Description'  => %q{
        This module will be applied on a session connected to a shell. It will
        extract current username.
      },
      'Author'       => 'Alberto Rafael Rodriguez Iglesias <security[at]vulnerateca.com> <albertocysec[at]gmail.com>',
      'License'      => MSF_LICENSE,
      'Platform'     => ['linux'],
      'SessionTypes' => ['shell']
    )
  end

  def run
    print_status("Doing whoami without whoami command")
    whoami_result=pepa_whoami()[0]
    print_line(whoami_result)
  end
end
