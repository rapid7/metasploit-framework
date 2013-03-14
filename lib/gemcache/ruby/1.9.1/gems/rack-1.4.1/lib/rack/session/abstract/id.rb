# AUTHOR: blink <blinketje@gmail.com>; blink#ruby-lang@irc.freenode.net
# bugrep: Andreas Zehnder

require 'time'
require 'rack/request'
require 'rack/response'
begin
  require 'securerandom'
rescue LoadError
  # We just won't get securerandom
end

module Rack

  module Session

    module Abstract
      ENV_SESSION_KEY = 'rack.session'.freeze
      ENV_SESSION_OPTIONS_KEY = 'rack.session.options'.freeze

      # Thin wrapper around Hash that allows us to lazily load session id into session_options.

      class OptionsHash < Hash #:nodoc:
        def initialize(by, env, default_options)
          @by = by
          @env = env
          @session_id_loaded = false
          merge!(default_options)
        end

        def [](key)
          load_session_id! if key == :id && session_id_not_loaded?
          super
        end

      private

        def session_id_not_loaded?
          !(@session_id_loaded || key?(:id))
        end

        def load_session_id!
          self[:id] = @by.send(:extract_session_id, @env)
          @session_id_loaded = true
        end
      end

      # SessionHash is responsible to lazily load the session from store.

      class SessionHash < Hash
        def initialize(by, env)
          super()
          @by = by
          @env = env
          @loaded = false
        end

        def [](key)
          load_for_read!
          super(key.to_s)
        end

        def has_key?(key)
          load_for_read!
          super(key.to_s)
        end
        alias :key? :has_key?
        alias :include? :has_key?

        def []=(key, value)
          load_for_write!
          super(key.to_s, value)
        end

        def clear
          load_for_write!
          super
        end

        def to_hash
          load_for_read!
          h = {}.replace(self)
          h.delete_if { |k,v| v.nil? }
          h
        end

        def update(hash)
          load_for_write!
          super(stringify_keys(hash))
        end

        def delete(key)
          load_for_write!
          super(key.to_s)
        end

        def inspect
          if loaded?
            super
          else
            "#<#{self.class}:0x#{self.object_id.to_s(16)} not yet loaded>"
          end
        end

        def exists?
          return @exists if instance_variable_defined?(:@exists)
          @exists = @by.send(:session_exists?, @env)
        end

        def loaded?
          @loaded
        end

        def empty?
          load_for_read!
          super
        end

      private

        def load_for_read!
          load! if !loaded? && exists?
        end

        def load_for_write!
          load! unless loaded?
        end

        def load!
          id, session = @by.send(:load_session, @env)
          @env[ENV_SESSION_OPTIONS_KEY][:id] = id
          replace(stringify_keys(session))
          @loaded = true
        end

        def stringify_keys(other)
          hash = {}
          other.each do |key, value|
            hash[key.to_s] = value
          end
          hash
        end
      end

      # ID sets up a basic framework for implementing an id based sessioning
      # service. Cookies sent to the client for maintaining sessions will only
      # contain an id reference. Only #get_session and #set_session are
      # required to be overwritten.
      #
      # All parameters are optional.
      # * :key determines the name of the cookie, by default it is
      #   'rack.session'
      # * :path, :domain, :expire_after, :secure, and :httponly set the related
      #   cookie options as by Rack::Response#add_cookie
      # * :skip will not a set a cookie in the response nor update the session state
      # * :defer will not set a cookie in the response but still update the session
      #   state if it is used with a backend
      # * :renew (implementation dependent) will prompt the generation of a new
      #   session id, and migration of data to be referenced at the new id. If
      #   :defer is set, it will be overridden and the cookie will be set.
      # * :sidbits sets the number of bits in length that a generated session
      #   id will be.
      #
      # These options can be set on a per request basis, at the location of
      # env['rack.session.options']. Additionally the id of the session can be
      # found within the options hash at the key :id. It is highly not
      # recommended to change its value.
      #
      # Is Rack::Utils::Context compatible.
      #
      # Not included by default; you must require 'rack/session/abstract/id'
      # to use.

      class ID
        DEFAULT_OPTIONS = {
          :key =>           'rack.session',
          :path =>          '/',
          :domain =>        nil,
          :expire_after =>  nil,
          :secure =>        false,
          :httponly =>      true,
          :defer =>         false,
          :renew =>         false,
          :sidbits =>       128,
          :cookie_only =>   true,
          :secure_random => (::SecureRandom rescue false)
        }

        attr_reader :key, :default_options

        def initialize(app, options={})
          @app = app
          @default_options = self.class::DEFAULT_OPTIONS.merge(options)
          @key = @default_options.delete(:key)
          @cookie_only = @default_options.delete(:cookie_only)
          initialize_sid
        end

        def call(env)
          context(env)
        end

        def context(env, app=@app)
          prepare_session(env)
          status, headers, body = app.call(env)
          commit_session(env, status, headers, body)
        end

        private

        def initialize_sid
          @sidbits = @default_options[:sidbits]
          @sid_secure = @default_options[:secure_random]
          @sid_length = @sidbits / 4
        end

        # Generate a new session id using Ruby #rand.  The size of the
        # session id is controlled by the :sidbits option.
        # Monkey patch this to use custom methods for session id generation.

        def generate_sid(secure = @sid_secure)
          if secure
            SecureRandom.hex(@sid_length)
          else
            "%0#{@sid_length}x" % Kernel.rand(2**@sidbits - 1)
          end
        rescue NotImplementedError
          generate_sid(false)
        end

        # Sets the lazy session at 'rack.session' and places options and session
        # metadata into 'rack.session.options'.

        def prepare_session(env)
          session_was                  = env[ENV_SESSION_KEY]
          env[ENV_SESSION_KEY]         = SessionHash.new(self, env)
          env[ENV_SESSION_OPTIONS_KEY] = OptionsHash.new(self, env, @default_options)
          env[ENV_SESSION_KEY].merge! session_was if session_was
        end

        # Extracts the session id from provided cookies and passes it and the
        # environment to #get_session.

        def load_session(env)
          sid = current_session_id(env)
          sid, session = get_session(env, sid)
          [sid, session || {}]
        end

        # Extract session id from request object.

        def extract_session_id(env)
          request = Rack::Request.new(env)
          sid = request.cookies[@key]
          sid ||= request.params[@key] unless @cookie_only
          sid
        end

        # Returns the current session id from the OptionsHash.

        def current_session_id(env)
          env[ENV_SESSION_OPTIONS_KEY][:id]
        end

        # Check if the session exists or not.

        def session_exists?(env)
          value = current_session_id(env)
          value && !value.empty?
        end

        # Session should be commited if it was loaded, any of specific options like :renew, :drop
        # or :expire_after was given and the security permissions match. Skips if skip is given.

        def commit_session?(env, session, options)
          if options[:skip]
            false
          else
            has_session = loaded_session?(session) || forced_session_update?(session, options)
            has_session && security_matches?(env, options)
          end
        end

        def loaded_session?(session)
          !session.is_a?(SessionHash) || session.loaded?
        end

        def forced_session_update?(session, options)
          force_options?(options) && session && !session.empty?
        end

        def force_options?(options)
          options.values_at(:renew, :drop, :defer, :expire_after).any?
        end

        def security_matches?(env, options)
          return true unless options[:secure]
          request = Rack::Request.new(env)
          request.ssl?
        end

        # Acquires the session from the environment and the session id from
        # the session options and passes them to #set_session. If successful
        # and the :defer option is not true, a cookie will be added to the
        # response with the session's id.

        def commit_session(env, status, headers, body)
          session = env['rack.session']
          options = env['rack.session.options']

          if options[:drop] || options[:renew]
            session_id = destroy_session(env, options[:id] || generate_sid, options)
            return [status, headers, body] unless session_id
          end

          return [status, headers, body] unless commit_session?(env, session, options)

          session.send(:load!) unless loaded_session?(session)
          session = session.to_hash
          session_id ||= options[:id] || generate_sid

          if not data = set_session(env, session_id, session, options)
            env["rack.errors"].puts("Warning! #{self.class.name} failed to save session. Content dropped.")
          elsif options[:defer] and not options[:renew]
            env["rack.errors"].puts("Defering cookie for #{session_id}") if $VERBOSE
          else
            cookie = Hash.new
            cookie[:value] = data
            cookie[:expires] = Time.now + options[:expire_after] if options[:expire_after]
            set_cookie(env, headers, cookie.merge!(options))
          end

          [status, headers, body]
        end

        # Sets the cookie back to the client with session id. We skip the cookie
        # setting if the value didn't change (sid is the same) or expires was given.

        def set_cookie(env, headers, cookie)
          request = Rack::Request.new(env)
          if request.cookies[@key] != cookie[:value] || cookie[:expires]
            Utils.set_cookie_header!(headers, @key, cookie)
          end
        end

        # All thread safety and session retrival proceedures should occur here.
        # Should return [session_id, session].
        # If nil is provided as the session id, generation of a new valid id
        # should occur within.

        def get_session(env, sid)
          raise '#get_session not implemented.'
        end

        # All thread safety and session storage proceedures should occur here.
        # Should return true or false dependant on whether or not the session
        # was saved or not.

        def set_session(env, sid, session, options)
          raise '#set_session not implemented.'
        end

        # All thread safety and session destroy proceedures should occur here.
        # Should return a new session id or nil if options[:drop]

        def destroy_session(env, sid, options)
          raise '#destroy_session not implemented'
        end
      end
    end
  end
end
