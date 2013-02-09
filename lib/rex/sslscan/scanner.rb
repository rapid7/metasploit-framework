require 'rex/socket'

module Rex::SSLScan

class Scanner

	attr_accessor :host
	attr_accessor :port
	attr_accessor :timeout

	def initialize(host,port,timeout=20)
		@host       = host
		@port       = port
		@timeout = timeout
		raise StandardError, "The supplied configuration is invalid" unless valid?
	end

	def valid?
		begin
			@host = Rex::Socket.getaddress(@host, true)
		rescue
			return false
		end
		return false unless @port.kind_of? Fixnum
		return false unless @port >= 0 and @port <= 65535
		return false unless @timeout.kind_of? Fixnum
		return true
	end

	def scan
		raise StandardError, "The supplied configuration is invalid" unless valid?
		scan_result = Rex::SSLScan::Result.new


	end

	def test_cipher(ssl_version, cipher)

	end

end
end