require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Core
# ----
#
# Core meterpreter client commands.
#
###
class Console::CommandDispatcher::Core

	include Console::CommandDispatcher

	def initialize(shell)
		super

		self.extensions = []
		self.ext_hash   = {}
	end

	@@use_opts = Rex::Parser::Arguments.new(
		"-h" => [ false, "Help menu."      ])

	#
	# List of supported commands
	#
	def commands
		{
			"?"        => "Help menu",
			"close"    => "Closes a channel",
			"channel"  => "Displays information about active channels",
			"exit"     => "Terminate the meterpreter session",
			"help"     => "Help menu",
			"interact" => "Interacts with a channel",
			"migrate"  => "Migrate the server to another process",
			"use"      => "Load a one or more meterpreter extensions",
			"quit"     => "Terminate the meterpreter session",
			"read"     => "Reads data from a channel",
			"write"    => "Writes data to a channel",
		}
	end

	#
	# Core baby.
	#
	def name
		"Core"
	end

	#
	# Displays information about active channels
	#
	@@channel_opts = Rex::Parser::Arguments.new(
		"-l" => [ false, "List active channels." ],
		"-h" => [ false, "Help menu."            ])

	def cmd_channel(*args)
		if (args.length == 0)
			args.unshift("-h")
		end

		mode = nil

		# Parse options
		@@channel_opts.parse(args) { |opt, idx, val|
			case opt
				when "-h"
					print(
						"Usage: channel [options]\n\n" +
						"Displays information about active channels.\n" +
						@@channel_opts.usage)
					return true
				when "-l"
					mode = 'list'
			end
		}

		# No mode, no service.
		if (mode == nil)
			return true
		elsif (mode == 'list')
			tbl = Rex::Ui::Text::Table.new(
				'Indent'  => 4,
				'Columns' => 
					[
						'Id',
						'Class',
						'Type'
					])
			items = 0

			client.channels.each_pair { |cid, channel|
				tbl << [ cid, channel.class.cls, channel.type ]
				items += 1
			}

			if (items == 0)
				print_line("No active channels.")
			else
				print("\n" + tbl.to_s + "\n")
			end
		end
	end

	#
	# Closes a supplied channel.
	#
	def cmd_close(*args)
		if (args.length == 0)
			print_line(
				"Usage: close channel_id\n\n" +
				"Closes the supplied channel.")
			return true
		end

		cid     = args[0].to_i
		channel = client.find_channel(cid)

		if (!channel)
			print_error("Invalid channel identifier specified.")
			return true
		else
			channel.close

			print_status("Closed channel #{cid}.")
		end
	end

	#
	# Terminates the meterpreter session.
	#
	def cmd_exit(*args)
		shell.stop
	end

	alias cmd_quit cmd_exit

	#
	# Displays the help menu.
	#
	def cmd_help(*args)
		print(shell.help_to_s)
	end

	alias cmd_? cmd_help

	#
	# Interacts with a channel.
	#
	def cmd_interact(*args)
		if (args.length == 0)
			print_line(
				"Usage: interact channel_id\n\n" +
				"Interacts with the supplied channel.")
			return true
		end

		cid     = args[0].to_i
		channel = client.find_channel(cid)

		if (channel)
			print_line("Interacting with channel #{cid}...\n")

			shell.interact_with_channel(channel)
		else
			print_error("Invalid channel identifier specified.")
		end
	end

	#
	# Migrates the server to the supplied process identifier.
	#
	def cmd_migrate(*args)
		if (args.length == 0)
			print_line(
				"Usage: migrate pid\n\n" +
				"Migrates the server instance to another process.\n" +
				"Note: Any open channels or other dynamic state will be lost.")
			return true
		end

		pid = args[0].to_i

		print_status("Migrating to #{pid}...")

		# Do this thang.
		client.core.migrate(pid)

		print_status("Migration completed successfully.")
	end

	#
	# Loads one or more meterpreter extensions.
	#
	def cmd_use(*args)
		if (args.length == 0)
			args.unshift("-h")
		end

		modules = nil

		@@use_opts.parse(args) { |opt, idx, val|
			case opt
				when "-h"
					print(
						"Usage: use ext1 ext2 ext3 ...\n\n" +
						"Loads a meterpreter extension module or modules.\n" +
						@use_opts.usage)
					return true
			end
		}

		# Load each of the modules
		args.each { |m|
			md = m.downcase

			if (extensions.include?(md))
				print_error("The '#{md}' extension has already been loaded.")
				next
			end

			print("Loading extension #{md}...")

			begin
				# Use the remote side, then load the client-side
				if (client.core.use(md) == true)
					add_extension_client(md)
				end
			rescue
				log_error("\nfailure: #{$!}")
				next
			end

			print_line("success.")
		}

		return true
	end

	#
	# Reads data from a channel.
	#
	def cmd_read(*args)
		if (args.length == 0)
			print_line(
				"Usage: read channel_id [length]\n\n" +
				"Reads data from the supplied channel.")
			return true
		end

		cid     = args[0].to_i
		length  = (args.length >= 2) ? args[1].to_i : 16384
		channel = client.find_channel(cid)

		if (!channel)
			print_error("Channel #{cid} is not valid.")
			return true
		end

		data = channel.read(length)

		if (data and data.length)
			print("Read #{data.length} bytes from #{cid}:\n\n#{data}\n")
		else
			print_error("No data was returned.")
		end
			
		return true
	end

	#
	# Writes data to a channel.
	#
	@@write_opts = Rex::Parser::Arguments.new(
		"-f" => [ true,  "Write the contents of a file on disk" ],
		"-h" => [ false, "Help menu."                           ])

	def cmd_write(*args)
		if (args.length == 0)
			args.unshift("-h")
		end

		src_file = nil
		cid      = nil

		@@write_opts.parse(args) { |opt, idx, val|
			case opt
				when "-h"
					print(
						"Usage: write [options] channel_id\n\n" +
						"Writes data to the supplied channel.\n" +
						@@write_opts.usage)
					return true
				when "-f"
					src_file = val
				else
					cid = val.to_i
			end
		}

		# Find the channel associated with this cid, assuming the cid is valid.
		if ((!cid) or
		    (!(channel = client.find_channel(cid))))
			print_error("Invalid channel identifier specified.")
			return true
		end

		# If they supplied a source file, read in its contents and write it to
		# the channel
		if (src_file)
			begin
				data = ::IO.readlines(src_file)
			rescue Errno::ENOENT
				print_error("Invalid source file specified: #{src_file}")
				return true
			end

			if (data and data.length)
				channel.write(data)
				print_status("Wrote #{data.length} bytes to channel #{cid}.")
			else
				print_error("No data to send from file #{src_file}")
				return true
			end
		# Otherwise, read from the input descriptor until we're good to go.
		else
			print("Enter data followed by a '.' on an empty line:\n\n")

			data = ''

			# Keep truckin'
			while (s = shell.input.gets)
				break if (s =~ /^\.\r?\n?$/)
				data += s
			end

			if (!data or data.length == 0)
				print_error("No data to send.")
			else
				channel.write(data)
				print_status("Wrote #{data.length} bytes to channel #{cid}.")
			end
		end

		return true
	end

protected

	attr_accessor :extensions, :ext_hash

	CommDispatcher = Console::CommandDispatcher

	#
	# Loads the client extension specified in mod
	#
	def add_extension_client(mod)
		clirb  = File.join(Rex::Root, "post/meterpreter/ui/console/command_dispatcher/#{mod}.rb")

		old = CommDispatcher.constants

		if (require(clirb) == true)
			new  = CommDispatcher.constants
			diff = new - old
	
			if (diff.empty? == true)
				print_error("Failed to load client portion of #{mod}.")
				return false
			end

			self.ext_hash[mod] = CommDispatcher.const_get(diff[0])
		end
	
		# Create the dispatcher	
		klass = self.ext_hash[mod]

		# Enstack the dispatcher
		self.shell.enstack_dispatcher(klass)

		# Insert the module into the list of extensions
		self.extensions << mod
	end
end

end
end
end
end
