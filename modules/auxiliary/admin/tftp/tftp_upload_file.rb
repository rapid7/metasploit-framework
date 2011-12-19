##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Rex::Proto::TFTP
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'TFTP File Transfer Utility',
			'Description' => %q{
					This module will send file to a remote TFTP server. Note that the target
					must be able to connect back to the Metasploit system, and NAT traversal
					for TFTP is often unsupported.
				},
			'Author'      => [ 'todb' ],
			'References'  =>
				[
					['URL', 'http://www.faqs.org/rfcs/rfc1350.html'],
					['URL', 'http://www.networksorcery.com/enp/protocol/tftp.htm']
				],
			'Actions' => [
				[ 'Download', {'Description' => "Download REMOTE_FILENAME as FILENAME."}],
				[ 'Upload', {'Description' => "Upload FILENAME as REMOTE_FILENAME to the server."}]
				],
			'DefaultAction' => 'Upload',
			'License'     => MSF_LICENSE
		)
		register_options([
			OptPath.new(   'FILENAME', [false, "The local filename" ]),
			OptString.new( 'REMOTE_FILENAME', [false, "The remote filename"]),
			OptAddress.new('RHOST',    [true, "The remote TFTP server"]),
			OptPort.new(   'LPORT',    [false, "The local port the TFTP client should listen on (default is random)" ]),
			OptAddress.new('LHOST',    [false, "The local address the TFTP client should bind to"]),
			OptBool.new(   'VERBOSE',  [false, "Display verbose details about the transfer", false]),
			OptString.new(  'MODE',    [false, "The TFTP mode; usual choices are netascii and octet.", "octet"]),
			Opt::RPORT(69)
		], self.class)
	end

	def file
		if action.name == "Upload"
			datastore['FILENAME']
		else # "Download
			fname = ::File.split(datastore['FILENAME'] || datastore['REMOTE_FILENAME']).last
		end
	end

	def mode
		datastore['MODE'] || "octect"
	end

	def remote_file
		datastore['REMOTE_FILENAME'] || ::File.split(datastore['FILENAME']).last
	end

	def rport
		datastore['RPORT'] || 69
	end

	def rhost
		datastore['RHOST']
	end

	def datatype
		case datastore['MODE']
		when "netascii"
			"text/plain"
		else
			"application/octet-stream"
		end
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

	def check_valid_filename
		not (datastore['FILENAME'].to_s.empty? and datastore['REMOTE_FILENAME'].to_s.empty?)
	end

	#
	# TFTP is a funny service and needs to kind of be a server on our side, too.
	def setup
		unless check_valid_filename()
			print_error "Need at least one valid filename."
			return
		end
		@lport = datastore['LPORT'] || (1025 + rand(0xffff-1025))
		@lhost = datastore['LHOST'] || "0.0.0.0"
		@local_file = file
		@remote_file = remote_file

		@tftp_client = Rex::Proto::TFTP::Client.new(
			"LocalHost" => @lhost,
			"LocalPort" => @lport,
			"PeerHost"  => rhost,
			"PeerPort"  => rport,
			"LocalFile" => @local_file,
			"RemoteFile" => @remote_file,
			"Mode"      => mode,
			"Action"    => action.name.to_s.downcase.intern
		)
	end

	def run
		return unless check_valid_filename()
		run_upload()   if action.name == 'Upload'
		run_download() if action.name == 'Download'
		while true
			if @tftp_client.complete
				print_status [rtarget,"TFTP transfer operation complete."].join
				if action.name == 'Download'
					save_downloaded_file()
				end
				break
			else
				select(nil,nil,nil,1)
			end
		end
	end

	def run_upload
		print_status "Sending '#{file}' to #{rhost}:#{rport} as '#{remote_file}'"
		@tftp_client.send_write_request { |msg| print_tftp_status(msg) }
	end

	def run_download
		print_status "Receiving '#{remote_file}' from #{rhost}:#{rport} as '#{file}'"
		@tftp_client.send_read_request { |msg| print_tftp_status(msg) }
	end

	def save_downloaded_file
		print_status "Saving #{remote_file} as #{file}"
		fh = @tftp_client.recv_tempfile
		data = File.open(fh,"rb") {|f| f.read f.stat.size} rescue nil
		if data and not data.empty?
			unless framework.db.active
				print_status "No database connected, so not actually saving the data:"
				print_line data
			end
			this_service = report_service(
				:host => rhost,
				:port => rport,
				:name => "tftp",
				:proto => "udp"
			)
			store_loot("tftp.file",datatype,rhost,data,file,remote_file,this_service)
		else
			print_status [rtarget,"Did not find any data, so nothing to save."].join
		end
		fh.unlink rescue nil # Windows often complains about unlinking tempfiles
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

