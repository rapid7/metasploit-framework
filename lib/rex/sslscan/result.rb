
require 'rex/socket'

module Rex::SSLScan
class Result

	attr_accessor :sslv2
	attr_accessor :sslv3
	attr_accessor :tlsv1

	attr_reader :supported_versions

	def initialize()
		@cert = nil
		@sslv2 = {}
		@sslv3 = {}
		@tlsv1 = {}
		@supported_versions = [:sslv2, :sslv3, :tlsv1]
	end

	def cert
		@cert
	end

	def cert=(input)
		unless input.kind_of? OpenSSL::X509::Certificate or input.nil?
			raise ArgumentError, "Must be an X509 Cert!" 
		end
		@cert = input
	end

	def add_cipher(version, cipher, key_length, status)
		
	end

end
end