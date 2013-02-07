
require 'rex/socket'

module Rex::SSLScan
class Result

	attr_reader :sslv2
	attr_reader :sslv3
	attr_reader :tlsv1
	attr_reader :supported_versions

	def initialize()
		@cert = nil
		@sslv2 = {:accepted => [], :rejected => []}
		@sslv3 = {:accepted => [], :rejected => []}
		@tlsv1 = {:accepted => [], :rejected => []}
		@supported_versions = [:SSLv2, :SSLv3, :TLSv1]
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
		unless @supported_versions.include? version
			raise ArgumentError, "Must be a supported SSL Version"
		end
		unless OpenSSL::SSL::SSLContext.new(version).ciphers.flatten.include? cipher
			raise ArgumentError, "Must be a valid SSL Cipher for #{version}!"
		end
		unless key_length.kind_of? Fixnum
			raise ArgumentError, "Must supply a valid key length"
		end
		unless [:accepted, :rejected].include? status
			raise ArgumentError, "status Must be either :accepted or :rejected"
		end

		cipher_details = {:cipher => cipher, :key_length => key_length}
		case version
		when :SSLv2
			@sslv2[status] << cipher_details
		when :SSLv3
			@sslv3[status] << cipher_details
		when :TLSv1
			@tlsv1[status] << cipher_details
		end
	end

	def accepted
		{
			:SSLv2 => @sslv2[:accepted],
			:SSLv3 => @sslv3[:accepted],
			:TLSv1 => @tlsv1[:accepted]
		}
	end

	def rejected
		{
			:SSLv2 => @sslv2[:rejected],
			:SSLv3 => @sslv3[:rejected],
			:TLSv1 => @tlsv1[:rejected]
		}
	end

	def each_accepted
		all_accepted = []

		accepted.each_pair do |version, cipher_list| 
			cipher_list.each do |cipher_details|
				cipher_details[:version] = version
				all_accepted << cipher_details
			end
		end
		all_accepted.each do |cipher_result|
			yield cipher_result
		end
	end

	def each_rejected
		all_rejected = []

		rejected.each_pair do |version, cipher_list| 
			cipher_list.each do |cipher_details|
				cipher_details[:version] = version
				all_rejected << cipher_details
			end
		end
		all_rejected.each do |cipher_result|
			yield cipher_result
		end
	end

	def supports_sslv2?
		!(accepted[:SSLv2].empty?)
	end

	def supports_sslv3?
		!(accepted[:SSLv3].empty?)
	end

	def supports_tlsv1?
		!(accepted[:TLSv1].empty?)
	end

	def supports_ssl?
		supports_sslv2? or supports_sslv3? or supports_tlsv1?
	end
end
end