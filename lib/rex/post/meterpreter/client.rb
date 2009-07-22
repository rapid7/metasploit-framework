#!/usr/bin/env ruby

require 'socket'
require 'openssl'

require 'rex/script'
require 'rex/post/meterpreter/client_core'
require 'rex/post/meterpreter/channel'
require 'rex/post/meterpreter/channel_container'
require 'rex/post/meterpreter/dependencies'
require 'rex/post/meterpreter/object_aliases'
require 'rex/post/meterpreter/packet'
require 'rex/post/meterpreter/packet_parser'
require 'rex/post/meterpreter/packet_dispatcher'

module Rex
module Post
module Meterpreter

#
# Just to get it in there...
#
module Extensions
end

###
#
# This class represents a logical meterpreter client class.  This class
# provides an interface that is compatible with the Rex post-exploitation
# interface in terms of the feature set that it attempts to expose.  This
# class is meant to drive a single meterpreter client session.
#
###
class Client

	include Rex::Post::Meterpreter::PacketDispatcher
	include Rex::Post::Meterpreter::ChannelContainer

	#
	# Extension name to class hash.
	#
	@@ext_hash = {}

	#
	# Checks the extension hash to see if a class has already been associated
	# with the supplied extension name.
	#
	def self.check_ext_hash(name)
		@@ext_hash[name]
	end

	#
	# Stores the name to class association for the supplied extension name.
	#
	def self.set_ext_hash(name, klass)
		@@ext_hash[name] = klass
	end

	#
	# Initializes the client context with the supplied socket through
	# which communication with the server will be performed.
	#
	def initialize(sock, to = self.class.default_timeout)
		init_meterpreter(sock, to)
	end

	#
	# Cleans up the meterpreter instance, terminating the dispatcher thread.
	#
	def cleanup_meterpreter
		dispatcher_thread.kill if dispatcher_thread
	end

	#
	# Initializes the meterpreter client instance
	#
	def init_meterpreter(sock, to = self.class.default_timeout)
		self.sock        = sock
		self.parser      = PacketParser.new
		self.ext         = ObjectAliases.new
		self.ext_aliases = ObjectAliases.new
		self.response_timeout = to
		
		# Switch the socket to SSL mode
		swap_sock_plain_to_ssl()

		register_extension_alias('core', ClientCore.new(self))

		initialize_inbound_handlers
		initialize_channels

		# Register the channel inbound packet handler
		register_inbound_handler(Rex::Post::Meterpreter::Channel)

		monitor_socket
	end

	def swap_sock_plain_to_ssl

		# Create a new SSL session on the existing socket
		ctx = generate_ssl_context()
		ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)

		ssl.accept

		sock.extend(Rex::Socket::SslTcp)		
		sock.sslsock = ssl
		sock.sslctx  = ctx

		tag = sock.read(18)
		if(not tag or tag != "GET / HTTP/1.0\r\n\r\n")
			raise RuntimeError, "Could not read the SSL hello tag"
		end
	end
	
	def swap_sock_ssl_to_plain
	
		# Remove references to the SSLSocket and Context
		self.sock.sslsock = nil
		self.sock.sslctx  = nil
		
		# Force garbage cleanup / SSL_free()
		GC.start()
		
		self.sock =  self.sock.fd
		self.sock.extend(::Rex::Socket::Tcp)
	end

	def generate_ssl_context
		key  = OpenSSL::PKey::RSA.new(1024){ }
		cert = OpenSSL::X509::Certificate.new
		cert.version = 2
		cert.serial  = rand(0xFFFFFFFF)
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
		cert.not_before = Time.now - (3600 * 365) + rand(3600 * 14)
		cert.not_after = Time.now + (3600 * 365) + rand(3600 * 14)
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
		
		ctx = OpenSSL::SSL::SSLContext.new(:TLSv1)
		ctx.key = key
		ctx.cert = cert

		ctx.session_id_context = OpenSSL::Digest::MD5.hexdigest(::Rex::Text.rand_text(64))

		return ctx
	end
	
	#
	# Loads the contents of the supplied file and executes it as a script using
	# the binding context of the session
	#
	def execute_file(file, in_binding = nil)
		client = self

		Rex::Script.execute_file(file, in_binding ? in_binding : binding)
	end

	##
	# 
	# Accessors
	#
	##

	#
	# Returns the default timeout that request packets will use when
	# waiting for a response.
	#
	def Client.default_timeout
		return 30
	end

	##
	#
	# Alias processor
	#
	##

	#
	# Translates unhandled methods into registered extension aliases
	# if a matching extension alias exists for the supplied symbol.
	#
	def method_missing(symbol, *args)
		self.ext_aliases.aliases[symbol.to_s]
	end

	##
	#
	# Extension registration
	#
	##

	#
	# Loads the client half of the supplied extension and initializes it as a
	# registered extension that can be reached through client.ext.[extension].
	#
	def add_extension(name)
		# Check to see if this extension has already been loaded.
		if ((klass = self.class.check_ext_hash(name.downcase)) == nil)
			old = Rex::Post::Meterpreter::Extensions.constants
			require("rex/post/meterpreter/extensions/#{name.downcase}/#{name.downcase}")
			new = Rex::Post::Meterpreter::Extensions.constants
	
			# No new constants added?
			if ((diff = new - old).empty?)
				return false
			end
	
			klass = Rex::Post::Meterpreter::Extensions.const_get(diff[0]).const_get(diff[0])

			# Save the module name to class association now that the code is
			# loaded.
			self.class.set_ext_hash(name.downcase, klass)
		end

		# Create a new instance of the extension
		inst = klass.new(self)

		self.ext.aliases[inst.name] = inst

		return true
	end

	#
	# Deregisters an extension alias of the supplied name.
	#
	def deregister_extension(name)
		self.ext.aliases.delete(name)
	end

	#
	# Enumerates all of the loaded extensions.
	#
	def each_extension(&block)
		self.ext.aliases.each(block)
	end

	#
	# Registers an aliased extension that can be referenced through
	# client.name.
	#
	def register_extension_alias(name, ext)
		self.ext_aliases.aliases[name] = ext
	end

	#
	# Registers zero or more aliases that are provided in an array.
	#
	def register_extension_aliases(aliases)
		aliases.each { |a|
			register_extension_alias(a['name'], a['ext'])
		}
	end

	#
	# Deregisters a previously registered extension alias.
	#
	def deregister_extension_alias(name)
		self.ext_aliases.aliases.delete(name)
	end

	#
	# Dumps the extension tree.
	#
	def dump_extension_tree()
		items = []
		items.concat(self.ext.dump_alias_tree('client.ext'))
		items.concat(self.ext_aliases.dump_alias_tree('client'))

		return items.sort
	end

	#
	# The extension alias under which all extensions can be accessed by name.
	# For example:
	#
	#    client.ext.stdapi
	#
	#
	attr_reader   :ext
	#
	# The socket the client is communicating over.
	#
	attr_reader   :sock
	#
	# The timeout value to use when waiting for responses.
	#
	attr_accessor :response_timeout
protected
	attr_accessor :parser, :ext_aliases # :nodoc:
	attr_writer   :ext, :sock # :nodoc:
end

end; end; end
