require 'rex/socket'
require 'rex/socket/tcp_server'
require 'rex/io/stream_server'

###
#
# This class provides methods for interacting with an SSL wrapped TCP server.  It
# implements the StreamServer IO interface.
#
###
module Rex::Socket::SslTcpServer

	@@loaded_openssl = false

	begin
		require 'openssl'
		@@loaded_openssl = true
	rescue ::Exception
	end


	include Rex::Socket::TcpServer

	##
	#
	# Factory
	#
	##

	def self.create(hash)
		self.create_param(Rex::Socket::Parameters.from_hash(hash))
	end

	#
	# Wrapper around the base class' creation method that automatically sets
	# the parameter's protocol to TCP and sets the server flag to true.
	#
	def self.create_param(param)
		param.proto  = 'tcp'
		param.server = true
		param.ssl    = true

		Rex::Socket.create_param(param)
	end

	def initsock(params = nil)
		raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl
		self.sslctx  = makessl()
		super
	end

	def accept(opts = {})
		sock = super()
		return if not sock

		begin
			ssl = OpenSSL::SSL::SSLSocket.new(sock, self.sslctx)
			ssl.accept
			sock.extend(Rex::Socket::SslTcp)
			sock.sslsock = ssl
			sock.sslctx  = self.sslctx
			return sock

		rescue ::OpenSSL::SSL::SSLError
			sock.close
			nil
		end
	end


	def makessl
		key = OpenSSL::PKey::RSA.new(1024){ }

		cert = OpenSSL::X509::Certificate.new
		cert.version = 2
		cert.serial = rand(0xFFFFFFFF)
		# name = OpenSSL::X509::Name.new([["C","JP"],["O","TEST"],["CN","localhost"]])
		subject = OpenSSL::X509::Name.new([
				["C","US"],
				['ST', Rex::Text.rand_state()],
				["L", Rex::Text.rand_text_alpha(rand(20) + 10)],
				["O", Rex::Text.rand_text_alpha(rand(20) + 10)],
				["CN", Rex::Text.rand_hostname],
			])
		issuer = OpenSSL::X509::Name.new([
				["C","US"],
				['ST', Rex::Text.rand_state()],
				["L", Rex::Text.rand_text_alpha(rand(20) + 10)],
				["O", Rex::Text.rand_text_alpha(rand(20) + 10)],
				["CN", Rex::Text.rand_hostname],
			])

		cert.subject = subject
		cert.issuer = issuer
		cert.not_before = Time.now - (3600 * 365)
		cert.not_after = Time.now + (3600 * 365)
		cert.public_key = key.public_key
		ef = OpenSSL::X509::ExtensionFactory.new(nil,cert)
		cert.extensions = [
			ef.create_extension("basicConstraints","CA:FALSE"),
			ef.create_extension("subjectKeyIdentifier","hash"),
			ef.create_extension("extendedKeyUsage","serverAuth"),
			ef.create_extension("keyUsage","keyEncipherment,dataEncipherment,digitalSignature")
		]
		ef.issuer_certificate = cert
		cert.add_extension ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
		cert.sign(key, OpenSSL::Digest::SHA1.new)

		ctx = OpenSSL::SSL::SSLContext.new()
		ctx.key = key
		ctx.cert = cert

		ctx.session_id_context = Rex::Text.rand_text(16)

		return ctx
	end

	attr_accessor :sslctx
end

