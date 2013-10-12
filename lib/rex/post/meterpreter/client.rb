#!/usr/bin/env ruby
# -*- coding: binary -*-

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
  # Cached SSL certificate (required to scale)
  #
  @@ssl_ctx = nil

  #
  # Mutex to synchronize class-wide operations
  #
  @@ssl_mutex = ::Mutex.new

  #
  # Lookup the error that occurred
  #
  def self.lookup_error(code)
    code
  end

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
  def initialize(sock,opts={})
    init_meterpreter(sock, opts)
  end

  #
  # Cleans up the meterpreter instance, terminating the dispatcher thread.
  #
  def cleanup_meterpreter
    ext.aliases.each_value do | extension |
      extension.cleanup if extension.respond_to?( 'cleanup' )
    end
    dispatcher_thread.kill if dispatcher_thread
    core.shutdown rescue nil
    shutdown_passive_dispatcher
  end

  #
  # Initializes the meterpreter client instance
  #
  def init_meterpreter(sock,opts={})
    self.sock         = sock
    self.parser       = PacketParser.new
    self.ext          = ObjectAliases.new
    self.ext_aliases  = ObjectAliases.new
    self.alive        = true
    self.target_id    = opts[:target_id]
    self.capabilities = opts[:capabilities] || {}
    self.commands     = []


    self.conn_id      = opts[:conn_id]
    self.url          = opts[:url]
    self.ssl          = opts[:ssl]
    self.expiration   = opts[:expiration]
    self.comm_timeout = opts[:comm_timeout]
    self.passive_dispatcher = opts[:passive_dispatcher]

    self.response_timeout = opts[:timeout] || self.class.default_timeout
    self.send_keepalives  = true
    # self.encode_unicode   = opts.has_key?(:encode_unicode) ? opts[:encode_unicode] : true
    self.encode_unicode = false

    if opts[:passive_dispatcher]
      initialize_passive_dispatcher

      register_extension_alias('core', ClientCore.new(self))

      initialize_inbound_handlers
      initialize_channels

      # Register the channel inbound packet handler
      register_inbound_handler(Rex::Post::Meterpreter::Channel)
    else
      # Switch the socket to SSL mode and receive the hello if needed
      if capabilities[:ssl] and not opts[:skip_ssl]
        swap_sock_plain_to_ssl()
      end

      register_extension_alias('core', ClientCore.new(self))

      initialize_inbound_handlers
      initialize_channels

      # Register the channel inbound packet handler
      register_inbound_handler(Rex::Post::Meterpreter::Channel)

      monitor_socket
    end
  end

  def swap_sock_plain_to_ssl
    # Create a new SSL session on the existing socket
    ctx = generate_ssl_context()
    ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)

    # Use non-blocking OpenSSL operations on Windows
    if !( ssl.respond_to?(:accept_nonblock) and Rex::Compat.is_windows )
      ssl.accept
    else
      begin
        ssl.accept_nonblock

      # Ruby 1.8.7 and 1.9.0/1.9.1 uses a standard Errno
      rescue ::Errno::EAGAIN, ::Errno::EWOULDBLOCK
          IO::Rex.sleep(0.10)
          retry

      # Ruby 1.9.2+ uses IO::WaitReadable/IO::WaitWritable
      rescue ::Exception => e
        if ::IO.const_defined?('WaitReadable') and e.kind_of?(::IO::WaitReadable)
          IO::select( [ ssl ], nil, nil, 0.10 )
          retry
        end

        if ::IO.const_defined?('WaitWritable') and e.kind_of?(::IO::WaitWritable)
          IO::select( nil, [ ssl ], nil, 0.10 )
          retry
        end

        raise e
      end
    end

    self.sock.extend(Rex::Socket::SslTcp)
    self.sock.sslsock = ssl
    self.sock.sslctx  = ctx

    tag = self.sock.get_once(-1, 30)
    if(not tag or tag !~ /^GET \//)
      raise RuntimeError, "Could not read the HTTP hello token"
    end
  end

  def swap_sock_ssl_to_plain
    # Remove references to the SSLSocket and Context
    self.sock.sslsock.close
    self.sock.sslsock = nil
    self.sock.sslctx  = nil
    self.sock = self.sock.fd
    self.sock.extend(::Rex::Socket::Tcp)
  end

  def generate_ssl_context
    @@ssl_mutex.synchronize do
    if not @@ssl_ctx

    wlog("Generating SSL certificate for Meterpreter sessions")

    key  = OpenSSL::PKey::RSA.new(1024){ }
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial  = rand(0xFFFFFFFF)

    # Depending on how the socket was created, getsockname will
    # return either a struct sockaddr as a String (the default ruby
    # Socket behavior) or an Array (the extend'd Rex::Socket::Tcp
    # behavior). Avoid the ambiguity by always picking a random
    # hostname. See #7350.
    subject_cn = Rex::Text.rand_hostname

    subject = OpenSSL::X509::Name.new([
        ["C","US"],
        ['ST', Rex::Text.rand_state()],
        ["L", Rex::Text.rand_text_alpha(rand(20) + 10)],
        ["O", Rex::Text.rand_text_alpha(rand(20) + 10)],
        ["CN", subject_cn],
      ])
    issuer = OpenSSL::X509::Name.new([
        ["C","US"],
        ['ST', Rex::Text.rand_state()],
        ["L", Rex::Text.rand_text_alpha(rand(20) + 10)],
        ["O", Rex::Text.rand_text_alpha(rand(20) + 10)],
        ["CN", Rex::Text.rand_text_alpha(rand(20) + 10)],
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

    ctx = OpenSSL::SSL::SSLContext.new(:SSLv3)
    ctx.key = key
    ctx.cert = cert

    ctx.session_id_context = Rex::Text.rand_text(16)

    wlog("Generated SSL certificate for Meterpreter sessions")

    @@ssl_ctx = ctx

    end # End of if not @ssl_ctx
    end # End of mutex.synchronize

    @@ssl_ctx
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
    return 300
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
    #$stdout.puts("method_missing: #{symbol}")
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
  def add_extension(name, commands=[])
    self.commands |= commands

    # Check to see if this extension has already been loaded.
    if ((klass = self.class.check_ext_hash(name.downcase)) == nil)
      old = Rex::Post::Meterpreter::Extensions.constants
      require("rex/post/meterpreter/extensions/#{name.downcase}/#{name.downcase}")
      new = Rex::Post::Meterpreter::Extensions.constants

      # No new constants added?
      if ((diff = new - old).empty?)
        diff = [ name.capitalize ]
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
    # Whee!  Syntactic sugar, where art thou?
    #
    # Create an instance method on this object called +name+ that returns
    # +ext+.  We have to do it this way instead of simply
    # self.class.class_eval so that other meterpreter sessions don't get
    # extension methods when this one does
    (class << self; self; end).class_eval do
      define_method(name.to_sym) do
        ext
      end
    end
    ext
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
  # Encodes (or not) a UTF-8 string
  #
  def unicode_filter_encode(str)
    self.encode_unicode ? Rex::Text.unicode_filter_encode(str) : str
  end

  #
  # Decodes (or not) a UTF-8 string
  #
  def unicode_filter_decode(str)
    self.encode_unicode ? Rex::Text.unicode_filter_decode(str) : str
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
  #
  # Whether to send pings every so often to determine liveness.
  #
  attr_accessor :send_keepalives
  #
  # Whether this session is alive.  If the socket is disconnected or broken,
  # this will be false
  #
  attr_accessor :alive
  #
  # The unique target identifier for this payload
  #
  attr_accessor :target_id
  #
  # The libraries available to this meterpreter server
  #
  attr_accessor :capabilities
  #
  # The Connection ID
  #
  attr_accessor :conn_id
  #
  # The Connect URL
  #
  attr_accessor :url
  #
  # Use SSL (HTTPS)
  #
  attr_accessor :ssl
  #
  # The Session Expiration Timeout
  #
  attr_accessor :expiration
  #
  # The Communication Timeout
  #
  attr_accessor :comm_timeout
  #
  # The Passive Dispatcher
  #
  attr_accessor :passive_dispatcher
  #
  # Flag indicating whether to hex-encode UTF-8 file names and other strings
  #
  attr_accessor :encode_unicode
  #
  # A list of the commands
  #
  attr_reader :commands

protected
  attr_accessor :parser, :ext_aliases # :nodoc:
  attr_writer   :ext, :sock # :nodoc:
  attr_writer   :commands # :nodoc:
end

end; end; end

