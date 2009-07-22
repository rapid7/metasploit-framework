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


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::FtpServer
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'FTP File Server',
			'Version'     => '$Revision$',
			'Description'    => %q{
				This module provides a FTP service
			},
			'Author'      => ['hdm'],
			'License'     => MSF_LICENSE,
			'Actions'     =>
				[
				 	[ 'Capture' ]
				],
			'PassiveActions' => 
				[
					'Capture'
				],
			'DefaultAction'  => 'Capture'
		)

		register_options(
			[
				OptString.new('FTPROOT',    [ true, "The FTP root directory to serve files from", '/tmp/ftproot' ])
			], self.class)
	end

	def run
		exploit()
	end

	def on_client_command_retr(c,arg)
		print_status("#{@state[c][:name]} FTP download request for #{arg}")

		path = ::File.join(datastore['FTPROOT'], arg.gsub("../", '').gsub("..\\", ''))
		if(not ::File.exists?(path))
			c.put "550 File does not exist\r\n"
			return
		end
		
		conn = establish_data_connection(c)
		if(not conn)
			c.put("425 Can't build data connection\r\n")
			return
		end
		
		c.put("150 Opening BINARY mode data connection for #{arg}\r\n")
		conn.put(::File.read(path, ::File.size(path)))
		c.put("226 Transfer complete.\r\n")
		conn.close
	end
	
	def on_client_command_list(c,arg)
		conn = establish_data_connection(c)
		if(not conn)
			c.put("425 Can't build data connection\r\n")
			return
		end

		pwd = datastore['FTPROOT']
		buf = ''
		Dir.new(pwd).entries.each do |ent|
			path = ::File.join(datastore['FTPROOT'], ent)
			if(::File.directory?(path))
				buf << "d--x--x--x   1 1            512 Jun 1  2001 #{ent}\r\n"
			end
			if(::File.file?(path))
				buf << "rwsx--r--r   1 1            512 Jun 1  2001 #{ent}\r\n"
			end			
		end
		
		c.put("150 Opening ASCII mode data connection for /bin/ls\r\n")
		conn.put("total #{buf.length}\r\n" + buf)
		c.put("226 Transfer complete.\r\n")	
		conn.close
	end
	
	def on_client_command_size(c,arg)
		path = ::File.join(datastore['FTPROOT'], arg.gsub("../", '').gsub("..\\", ''))
		if(not ::File.exists?(path))
			c.put "550 File does not exist\r\n"
			return
		end
		
		c.put("213 #{::File.size(path)}\r\n")
	end

end
