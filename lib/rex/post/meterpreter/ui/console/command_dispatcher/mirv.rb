require 'rex/post/meterpreter'

module Rex
	module Post
		module Meterpreter
			module Ui
				
				###
				#
				# Mirv command dispatcher
				#
				###
				class Console::CommandDispatcher::Mirv
					
					Klass = Console::CommandDispatcher::Mirv
					
					include Console::CommandDispatcher
					
					#
					# Initializes an instance of the priv command interaction.
					#
					def initialize(shell)
						super
					end
					
					#
					# List of supported commands.
					#
					def commands
						{
							"luado" => "Do lua code",	
							"luathread" => "Do lua code in thread",
							"threadstop" => "Stop a thread",
							"thread_list" => "List running threads"
						}
					end
					
					#	@@luado_opts = Rex::Parser::Arguments.new(
					#		"-c" => [ true,  "Lua code, if blank, returns Lua version" ])
					
					@@stopthread_opts = Rex::Parser::Arguments.new(
						"-t" => [ true,  "Thread ID" ])
					def cmd_thread_list(*args)
						client.Mirv.mirv_thread_list().each {|e|
							print e+"\n"
						}
					end
					def cmd_luado(*args)
						if args.length then
							payload=args.join(" ")
						else
							payload="return _VERSION"
						end
						if payload.start_with? "@" then
							payload=IO::File.new(payload[1..-1],"r").read
						else
							if not payload.start_with? "return" then
								payload = "return " + payload
							end
						end
						#print "Sending #{payload}\n for execution by Lua"		
						
						
						
						p=client.Mirv.mirv_luado(payload)
						print p+"\n"
						
						return true
					end
					
					def cmd_luathread(*args)
						if args.length then
							payload=args.join(" ")
						else
							payload="return _VERSION"
						end
						
						if payload.start_with? "@" then
							payload=IO::File.new(payload[1..-1],"r").read
						else
							if not payload.start_with? "return" then
								payload = "return " + payload
							end
						end
						#puts "Payload is #{payload}
						puts "Sending #{payload}\n for execution by Lua"		
						
						
						
						p=client.Mirv.mirv_luado(payload,true)
						print p+"\n"
						
						return true
					end
					
					#
					# Name for this dispatcher
					#
					def name
						"Mirv"
					end
					
				end
				
			end
		end
	end
end
