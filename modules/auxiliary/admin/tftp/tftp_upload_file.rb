##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Rex::Proto::TFTP

	def initialize
		super(
			'Name'        => 'TFTP File Transfer Utility',
			'Description' => %q{
					This module will send file to a remote TFTP server. Note that the target
					must be able to connect back to the Metasploit system, and NAT traversal
					for TFTP is often unsupported.
				},
			'Author'      => [ 'todb' ],
			'License'     => MSF_LICENSE
		)
		register_options([
			OptPath.new('FILENAME', [true, "The local file to upload" ]),
			OptString.new('REMOTE_FILENAME', [false, "The filename to provide to the TFTP server" ]),
			OptAddress.new('RHOST', [true, "The remote TFTP server"]),
			OptPort.new('LPORT',    [false, "The local port the TFTP client should listen on" ]),
			OptAddress.new('LHOST', [false, "The local address the TFTP client should bind to"]),
			OptBool.new('VERBOSE', [false, "Provide more details about the transfer", false]),
			OptString.new('MODE', [false, "The TFTP mode. Usual choices are netsacii and octet.", "octet"]),
			Opt::RPORT(69)
		], self.class)
	end

	def file
		datastore['FILENAME']
	end

	def mode
		datastore['MODE'] || "octect"
	end

	def remote_file
		datastore['REMOTE_FILENAME'] || ::File.split(file).last
	end

	def rport
		datastore['RPORT']
	end

	def rhost
		datastore['RHOST']
	end

	def rtarget(ip=nil)
		if (ip or rhost) and rport
			[(ip || rhost),rport].map {|x| x.to_s}.join(":") << " "
		elsif (ip or rhost)
			"#{rhost} "
		else
			""
		end
	end

	#
	# TFTP is a funny service and needs to kind of be a server on our side, too.
	def setup
		@rport = datastore['RPORT'] || 69
		@lport = datastore['LPORT'] || (1025 + rand(0xffff-1025))
		@lhost = datastore['LHOST'] || "0.0.0.0"
		@path     = datastore['FILENAME']
		@filename = ::File.split(@path).last

		@tftp_client = Rex::Proto::TFTP::Client.new(
			"LocalHost" => @lhost,
			"LocalPort" => @lport,
			"PeerHost"  => rhost,
			"PeerPort"  => rport,
			"LocalFile" => file,
			"RemoteFile" => remote_file,
			"Mode"      => mode
		)
	end

	def run
		print_status "Sending '#{file}' to #{@lhost}:#{@lport} as '#{remote_file}'"
		@tftp_client.send_write_request do |msg|
			print_tftp_status(msg)
		end
		while true
			if @tftp_client.complete
				print_status [rtarget,"TFTP transfer operation complete."].join
				break
			else
				select(nil,nil,nil,1)
			end
		end
	end

	def print_tftp_status(msg)
		case msg
		when /Aborting/, /errors.$/
			print_error [rtarget,msg].join
		when /^WRQ accepted/, /^Sending/, /complete!$/
			print_good [rtarget,msg].join
		else
			vprint_status [rtarget,msg].join 
		end
	end

end

