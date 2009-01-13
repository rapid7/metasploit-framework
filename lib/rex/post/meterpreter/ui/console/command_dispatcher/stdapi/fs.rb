require 'tempfile'
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# The file system portion of the standard API extension.
#
###
class Console::CommandDispatcher::Stdapi::Fs

	Klass = Console::CommandDispatcher::Stdapi::Fs

	include Console::CommandDispatcher

	#
	# Options for the download command.
	#
	@@download_opts = Rex::Parser::Arguments.new(
		"-r" => [ false, "Download recursively." ])
	#
	# Options for the upload command.
	#
	@@upload_opts = Rex::Parser::Arguments.new(
		"-r" => [ false, "Upload recursively." ])

	#
	# List of supported commands.
	#
	def commands
		{
			"cat"      => "Read the contents of a file to the screen",
			"cd"       => "Change directory",
			"download" => "Download a file or directory",
			"edit"     => "Edit a file",
			"getwd"    => "Print working directory",
			"ls"       => "List files",
			"mkdir"    => "Make directory",
			"pwd"      => "Print working directory",
			"rmdir"    => "Remove directory",
			"upload"   => "Upload a file or directory",
			"lcd"      => "Change local working directory",
			"getlwd"   => "Print local working directory",
			"lpwd"     => "Print local working directory"
		}
	end

	#
	# Name for this dispatcher.
	#
	def name
		"Stdapi: File system"
	end

	#
	# Reads the contents of a file and prints them to the screen.
	#
	def cmd_cat(*args)
		if (args.length == 0)
			print_line("Usage: cat file")
			return true
		end

		fd = client.fs.file.new(args[0], "rb")

		until fd.eof?
			print(fd.read)
		end

		fd.close

		true
	end

	#
	# Change the working directory.
	#
	def cmd_cd(*args)
		if (args.length == 0)
			print_line("Usage: cd directory")
			return true
		end

		client.fs.dir.chdir(args[0])

		return true
	end

	#
	# Change the local working directory.
	#
	def cmd_lcd(*args)
		if (args.length == 0)
			print_line("Usage: lcd directory")
			return true
		end

		::Dir.chdir(args[0])

		return true
	end
	
	#
	# Downloads a file or directory from the remote machine to the local
	# machine.
	#
	def cmd_download(*args)
		if (args.empty?)
			print(
				"Usage: download [options] src1 src2 src3 ... destination\n\n" +
				"Downloads remote files and directories to the local machine.\n" +
				@@download_opts.usage)
			return true
		end

		recursive = false
		src_items = []
		last      = nil
		dest      = nil

		@@download_opts.parse(args) { |opt, idx, val|
			case opt
				when "-r"
					recursive = true
				when nil
					if (last)
						src_items << last
					end

					last = val
			end
		}

		return true if not last

		# Source and destination will be the same
		src_items << last if src_items.empty?

		dest = last

		# Go through each source item and download them
		src_items.each { |src|
			stat = client.fs.file.stat(src)

			if (stat.directory?)
				client.fs.dir.download(dest, src, recursive) { |step, src, dst|
					print_status("#{step.ljust(11)}: #{src} -> #{dst}")
				}
			elsif (stat.file?)
				client.fs.file.download(dest, src) { |step, src, dst|
					print_status("#{step.ljust(11)}: #{src} -> #{dst}")
				}
			end
		}
		
		return true
	end

	#
	# Downloads a file to a temporary file, spawns and editor, and then uploads
	# the contents to the remote machine after completion.
	#
	def cmd_edit(*args)
		if (args.length == 0)
			print_line("Usage: edit file")
			return true
		end

		# Get a temporary file path
		temp_path = Tempfile.new('meterp').path

		begin
			# Download the remote file to the temporary file
			client.fs.file.download_file(temp_path, args[0])
		rescue RequestError => re
			# If the file doesn't exist, then it's okay.  Otherwise, throw the
			# error.
			if re.result != 2
				raise $!
			end
		end

		# Spawn the editor (default to vi)
		editor = Rex::Compat.getenv('EDITOR') || 'vi'

		# If it succeeds, upload it to the remote side.
		if (system("#{editor} #{temp_path}") == true)
			client.fs.file.upload_file(args[0], temp_path)
		end

		# Get rid of that pesky temporary file
		::File.unlink(temp_path)
	end

	#
	# Display the local working directory.
	#
	def cmd_lpwd(*args)
		print_line(::Dir.pwd)
		return true
	end

	alias cmd_getlwd cmd_lpwd

	#
	# Lists files
	#
	# TODO: make this more useful
	#
	def cmd_ls(*args)
		path = args[0] || client.fs.dir.getwd
		tbl  = Rex::Ui::Text::Table.new(
			'Header'  => "Listing: #{path}",
			'Columns' => 
				[
					'Mode',
					'Size',
					'Type',
					'Last modified',
					'Name',
				])

		items = 0

		# Enumerate each item...
		client.fs.dir.entries_with_info(path).sort { |a,b| a['FileName'] <=> b['FileName'] }.each { |p|

			tbl << 
				[ 
					p['StatBuf'] ? p['StatBuf'].prettymode : '',
					p['StatBuf'] ? p['StatBuf'].size       : '', 
					p['StatBuf'] ? p['StatBuf'].ftype[0,3] : '', 
					p['StatBuf'] ? p['StatBuf'].mtime      : '', 
					p['FileName'] || 'unknown'
				]

			items += 1
		}

		if (items > 0)
			print("\n" + tbl.to_s + "\n")
		else
			print_line("No entries exist in #{path}")
		end

		return true
	end

	#
	# Make one or more directory.
	#
	def cmd_mkdir(*args)
		if (args.length == 0)
			print_line("Usage: mkdir dir1 dir2 dir3 ...")
			return true
		end

		args.each { |dir|
			print_line("Creating directory: #{dir}")

			client.fs.dir.mkdir(dir)
		}

		return true
	end

	#
	# Display the working directory.
	#
	def cmd_pwd(*args)
		print_line(client.fs.dir.getwd)
	end

	alias cmd_getwd cmd_pwd

	#
	# Removes one or more directory if it's empty.
	#
	def cmd_rmdir(*args)
		if (args.length == 0)
		 	print_line("Usage: rmdir dir1 dir2 dir3 ...")
			return true
		end

		args.each { |dir|
			print_line("Removing directory: #{dir}")
			client.fs.dir.rmdir(dir)
		}

		return true
	end

	#
	# Uploads a file or directory to the remote machine from the local
	# machine.
	#
	def cmd_upload(*args)
		if (args.empty?)
			print(
				"Usage: upload [options] src1 src2 src3 ... destination\n\n" +
				"Uploads local files and directories to the remote machine.\n" +
				@@upload_opts.usage)
			return true
		end

		recursive = false
		src_items = []
		last      = nil
		dest      = nil

		@@upload_opts.parse(args) { |opt, idx, val|
			case opt
				when "-r"
					recursive = true
				when nil
					if (last)
						src_items << last
					end

					last = val
			end
		}

		return true if not last

		# Source and destination will be the same
		src_items << last if src_items.empty?

		dest = last

		# Go through each source item and upload them
		src_items.each { |src|
			stat = ::File.stat(src)

			if (stat.directory?)
				client.fs.dir.upload(dest, src, recursive) { |step, src, dst|
					print_status("#{step.ljust(11)}: #{src} -> #{dst}")
				}
			elsif (stat.file?)
				client.fs.file.upload(dest, src) { |step, src, dst|
					print_status("#{step.ljust(11)}: #{src} -> #{dst}")
				}
			end
		}
		
		return true
	end

end

end
end
end
end
