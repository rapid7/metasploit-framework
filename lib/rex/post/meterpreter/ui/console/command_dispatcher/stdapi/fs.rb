# -*- coding: binary -*-
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
		"-h" => [ false, "Help banner." ],
		"-r" => [ false, "Download recursively." ])
	#
	# Options for the upload command.
	#
	@@upload_opts = Rex::Parser::Arguments.new(
		"-h" => [ false, "Help banner." ],
		"-r" => [ false, "Upload recursively." ])

	#
	# List of supported commands.
	#
	def commands
		all = {
			"cat"      => "Read the contents of a file to the screen",
			"cd"       => "Change directory",
			"del"      => "Delete the specified file",
			"download" => "Download a file or directory",
			"edit"     => "Edit a file",
			"getlwd"   => "Print local working directory",
			"getwd"    => "Print working directory",
			"lcd"      => "Change local working directory",
			"lpwd"     => "Print local working directory",
			"ls"       => "List files",
			"mkdir"    => "Make directory",
			"pwd"      => "Print working directory",
			"rm"       => "Delete the specified file",
			"mv"	   => "Move source to destination",
			"rmdir"    => "Remove directory",
			"search"   => "Search for files",
			"upload"   => "Upload a file or directory",
		}

		reqs = {
			"cat"      => [ ],
			"cd"       => [ "stdapi_fs_chdir" ],
			"del"      => [ "stdapi_fs_rm" ],
			"download" => [ ],
			"edit"     => [ ],
			"getlwd"   => [ ],
			"getwd"    => [ "stdapi_fs_getwd" ],
			"lcd"      => [ ],
			"lpwd"     => [ ],
			"ls"       => [ "stdapi_fs_stat", "stdapi_fs_ls" ],
			"mkdir"    => [ "stdapi_fs_mkdir" ],
			"pwd"      => [ "stdapi_fs_getwd" ],
			"rmdir"    => [ "stdapi_fs_delete_dir" ],
			"rm"       => [ "stdapi_fs_delete_file" ],
			"mv"       => [ "stdapi_fs_file_move" ],
			"search"   => [ "stdapi_fs_search" ],
			"upload"   => [ ],
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

	#
	# Name for this dispatcher.
	#
	def name
		"Stdapi: File system"
	end

	#
	# Search for files.
	#
	def cmd_search( *args )

		root    = nil
		glob    = nil
		recurse = true

		opts = Rex::Parser::Arguments.new(
			"-h" => [ false, "Help Banner." ],
			"-d" => [ true,  "The directory/drive to begin searching from. Leave empty to search all drives. (Default: #{root})" ],
			"-f" => [ true,  "The file pattern glob to search for. (e.g. *secret*.doc?)" ],
			"-r" => [ true,  "Recursivly search sub directories. (Default: #{recurse})" ]
		)

		opts.parse(args) { | opt, idx, val |
			case opt
				when "-h"
					print_line( "Usage: search [-d dir] [-r recurse] -f pattern" )
					print_line( "Search for files." )
					print_line( opts.usage )
					return
				when "-d"
					root = val
				when "-f"
					glob = val
				when "-r"
					recurse = false if( val =~ /^(f|n|0)/i )
			end
		}

		if( not glob )
			print_error( "You must specify a valid file glob to search for, e.g. >search -f *.doc" )
			return
		end

		files = client.fs.file.search( root, glob, recurse )

		if( not files.empty? )
			print_line( "Found #{files.length} result#{ files.length > 1 ? 's' : '' }..." )
			files.each do | file |
				if( file['size'] > 0 )
					print( "    #{file['path']}#{ file['path'].empty? ? '' : '\\' }#{file['name']} (#{file['size']} bytes)\n" )
				else
					print( "    #{file['path']}#{ file['path'].empty? ? '' : '\\' }#{file['name']}\n" )
				end
			end
		else
			print_line( "No files matching your search were found." )
		end

	end

	#
	# Reads the contents of a file and prints them to the screen.
	#
	def cmd_cat(*args)
		if (args.length == 0)
			print_line("Usage: cat file")
			return true
		end

		if (client.fs.file.stat(args[0]).directory?)
			print_error("#{args[0]} is a directory")
		else
			fd = client.fs.file.new(args[0], "rb")
			begin
				until fd.eof?
					print(fd.read)
				end
			# EOFError is raised if file is empty, do nothing, just catch
			rescue EOFError
			end
			fd.close
		end

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
		if args[0] =~ /\%(\w*)\%/
			client.fs.dir.chdir(client.fs.file.expand_path(args[0].upcase))
		else
			client.fs.dir.chdir(args[0])
		end

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
	# Delete the specified file.
	#
	def cmd_rm(*args)
		if (args.length == 0)
			print_line("Usage: rm file")
			return true
		end

		client.fs.file.rm(args[0])

		return true
	end

	alias :cmd_del :cmd_rm

        #   
        # Move source to destination
        #   
        def cmd_mv(*args)
                if (args.length < 2)
                        print_line("Usage: mv oldfile newfile")
                        return true
                end 

                client.fs.file.mv(args[0],args[1])

                return true
        end 

        alias :cmd_move :cmd_mv
	alias :cmd_rename :cmd_mv


	def cmd_download_help
		print_line "Usage: download [options] src1 src2 src3 ... destination"
		print_line
		print_line "Downloads remote files and directories to the local machine."
		print_line @@download_opts.usage
	end

	#
	# Downloads a file or directory from the remote machine to the local
	# machine.
	#
	def cmd_download(*args)
		if (args.empty? or args.include? "-h")
			cmd_download_help
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
				src_items << last if (last)
				last = val
			end
		}

		# No files given, nothing to do
		if not last
			cmd_download_help
			return true
		end

		# Source and destination will be the same
		if src_items.empty?
			src_items << last
			# Use the basename of the remote filename so we don't end up with
			# a file named c:\\boot.ini in linux
			dest = ::Rex::Post::Meterpreter::Extensions::Stdapi::Fs::File.basename(last)
		else
			dest = last
		end

		# Go through each source item and download them
		src_items.each { |src|
			stat = client.fs.file.stat(src)

			if (stat.directory?)
				client.fs.dir.download(dest, src, recursive, true) { |step, src, dst|
					print_status("#{step.ljust(11)}: #{src} -> #{dst}")
					client.framework.events.on_session_download(client, src, dest) if msf_loaded?
				}
			elsif (stat.file?)
				client.fs.file.download(dest, src) { |step, src, dst|
					print_status("#{step.ljust(11)}: #{src} -> #{dst}")
					client.framework.events.on_session_download(client, src, dest) if msf_loaded?
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
		meterp_temp = Tempfile.new('meterp')
		meterp_temp.binmode
		temp_path = meterp_temp.path

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
		::File.delete(temp_path) rescue nil
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
			'SortIndex' => 4,
			'Columns' =>
				[
					'Mode',
					'Size',
					'Type',
					'Last modified',
					'Name',
				])

		items = 0
		stat = client.fs.file.stat(path)
		if stat.directory?
			# Enumerate each item...
			# No need to sort as Table will do it for us
			client.fs.dir.entries_with_info(path).each { |p|

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
		else
			print_line("#{stat.prettymode}  #{stat.size}  #{stat.ftype[0,3]}  #{stat.mtime}  #{path}")
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
		if (args.length == 0 or args.include?("-h"))
			print_line("Usage: rmdir dir1 dir2 dir3 ...")
			return true
		end

		args.each { |dir|
			print_line("Removing directory: #{dir}")
			client.fs.dir.rmdir(dir)
		}

		return true
	end

	def cmd_upload_help
		print_line "Usage: upload [options] src1 src2 src3 ... destination"
		print_line
		print_line "Uploads local files and directories to the remote machine."
		print_line @@upload_opts.usage
	end

	#
	# Uploads a file or directory to the remote machine from the local
	# machine.
	#
	def cmd_upload(*args)
		if (args.empty? or args.include?("-h"))
			cmd_upload_help
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
					client.framework.events.on_session_upload(client, src, dest) if msf_loaded?
				}
			elsif (stat.file?)
				client.fs.file.upload(dest, src) { |step, src, dst|
					print_status("#{step.ljust(11)}: #{src} -> #{dst}")
					client.framework.events.on_session_upload(client, src, dest) if msf_loaded?
				}
			end
		}

		return true
	end

	def cmd_upload_tabs(str, words)
		return [] if words.length > 1

		tab_complete_filenames(str, words)
	end

end

end
end
end
end
