##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Vulnerateca

  def initialize
    super(
      'Name'         => 'Vulnerateca List Directory (ls without ls)',
      'Description'  => %q{
        This module will be applied on a session connected to a shell. It will
        extract a list of files and folders on a given dir.
      },
	      'Author'       => 'Alberto Rafael Rodriguez Iglesias <security[at]vulnerateca.com> <albertocysec[at]gmail.com>',
      'License'      => MSF_LICENSE,
      'Platform'     => ['linux'],
      'SessionTypes' => ['shell']
    )
    register_options(
      [
        OptString.new('DIR', [false, 'Optional directory name to list, default current session path',''])
      ])
  end

  def run
    dir = datastore['DIR']
    if dir == ""
    	print_status("Doing ls without ls command in current session path DIR")
    else
	print_status("Doing ls without ls command in DIR: #{dir}")
    end
    ls_result=vulnerateca_ls(dir)
    ls_result.each do |line|
	print_line(line)
    end
    print_line("\n")
  end
end
