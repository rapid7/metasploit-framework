# -*- coding: binary -*-

##
#
# This Auxiliary Mixin provides functionality for dealing with BSD R*Services
#
##

module Msf
module Auxiliary::RServices

	def initialize(info = {})
		super

		register_options(
			[
				OptString.new('FROMUSER',      [ false, 'The username to login from' ]),
				OptPath.new(  'FROMUSER_FILE', [ false, 'File containing from usernames, one per line',
					File.join(Msf::Config.data_directory, "wordlists", "rservices_from_users.txt") ])
			], Msf::Auxiliary::RServices)

		register_advanced_options(
			[
	      	OptBool.new('REMOVE_FROMUSER_FILE', [ true, "Automatically delete the FROMUSER_FILE on module completion", false])
			], Msf::Auxiliary::RServices)
	end


	def connect_from_privileged_port(start_port = 1023)
		cport = start_port
		sd = nil
		while cport > 512
			#vprint_status("Trying to connect from port #{cport} ...")
			sd = nil
			begin
				sd = connect(true, { 'CPORT' => cport })

			rescue Rex::AddressInUse
				# Ignore and try again
				#vprint_error("Unable to connect: #{$!}")

			rescue Rex::ConnectionError => e
				vprint_error("Unable to connect: #{$!}")
				return :refused if e.class == Rex::ConnectionRefused
				return :connection_error

			end

			break if sd
			cport -= 1
		end

		if not sd
			print_error("#{target_host}:#{rport} - Unable to bind to privileged port")
			return :bind_error
		end

		#vprint_status("Connected from #{cport}")
		return :connected
	end


	def load_fromuser_vars
		fromusers = extract_words(datastore['FROMUSER_FILE'])
		if datastore['FROMUSER']
			fromusers.unshift datastore['FROMUSER']
		end
		fromusers
	end


	def cleanup_files
		super

		path = datastore['FROMUSER_FILE']
		if path and datastore['REMOVE_FROMUSER_FILE']
			::File.unlink(path) rescue nil
		end
	end

end
end
