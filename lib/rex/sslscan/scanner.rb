require 'rex/socket'

module Rex::SSLScan

class Scanner

	attr_accessor :host
	attr_accessor :port
	attr_accessor :timeout
	
	attr_reader :supported_versions

	def initialize(host,port = 443,timeout=20)
		@host       = host
		@port       = port
		@timeout = timeout
		@supported_versions = [:SSLv2, :SSLv3, :TLSv1]
		raise StandardError, "The scanner configuration is invalid" unless valid?
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
		scan_result = Rex::SSLScan::Result.new
	end

	def test_cipher(ssl_version, cipher)
		validate_params(ssl_version,cipher)

		begin
			scan_client = Rex::Socket::Tcp.create(
				'PeerHost'     => @host,
				'PeerPort'      => @port,
				'SSL'               => true,
				'SSLVersion'  => ssl_version,
				'SSLCipher'   => cipher,
				'Timeout'      => @timeout
			)
		rescue ::Exception => e 
			return :rejected
		end
		return :accepted
	end


	protected

	def validate_params(ssl_version, cipher)
		raise StandardError, "The scanner configuration is invalid" unless valid?
		unless @supported_versions.include? ssl_version
			raise StandardError, "SSL Version must be one of: #{@supported_versions.to_s}"
		end
		unless OpenSSL::SSL::SSLContext.new(ssl_version).ciphers.flatten.include? cipher
			raise ArgumentError, "Must be a valid SSL Cipher for #{version}!"
		end
	end

end
end