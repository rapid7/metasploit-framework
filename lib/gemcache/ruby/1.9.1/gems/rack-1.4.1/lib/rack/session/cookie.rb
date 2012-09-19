require 'openssl'
require 'rack/request'
require 'rack/response'
require 'rack/session/abstract/id'

module Rack

  module Session

    # Rack::Session::Cookie provides simple cookie based session management.
    # By default, the session is a Ruby Hash stored as base64 encoded marshalled
    # data set to :key (default: rack.session).  The object that encodes the
    # session data is configurable and must respond to +encode+ and +decode+.
    # Both methods must take a string and return a string.
    #
    # When the secret key is set, cookie data is checked for data integrity.
    # The old secret key is also accepted and allows graceful secret rotation.
    #
    # Example:
    #
    #     use Rack::Session::Cookie, :key => 'rack.session',
    #                                :domain => 'foo.com',
    #                                :path => '/',
    #                                :expire_after => 2592000,
    #                                :secret => 'change_me',
    #                                :old_secret => 'also_change_me'
    #
    #     All parameters are optional.
    #
    # Example of a cookie with no encoding:
    #
    #   Rack::Session::Cookie.new(application, {
    #     :coder => Rack::Session::Cookie::Identity.new
    #   })
    #
    # Example of a cookie with custom encoding:
    #
    #   Rack::Session::Cookie.new(application, {
    #     :coder => Class.new {
    #       def encode(str); str.reverse; end
    #       def decode(str); str.reverse; end
    #     }.new
    #   })
    #

    class Cookie < Abstract::ID
      # Encode session cookies as Base64
      class Base64
        def encode(str)
          [str].pack('m')
        end

        def decode(str)
          str.unpack('m').first
        end

        # Encode session cookies as Marshaled Base64 data
        class Marshal < Base64
          def encode(str)
            super(::Marshal.dump(str))
          end

          def decode(str)
            ::Marshal.load(super(str)) rescue nil
          end
        end
      end

      # Use no encoding for session cookies
      class Identity
        def encode(str); str; end
        def decode(str); str; end
      end

      # Reverse string encoding. (trollface)
      class Reverse
        def encode(str); str.reverse; end
        def decode(str); str.reverse; end
      end

      attr_reader :coder

      def initialize(app, options={})
        @secrets = options.values_at(:secret, :old_secret).compact
        @coder  = options[:coder] ||= Base64::Marshal.new
        super(app, options.merge!(:cookie_only => true))
      end

      private

      def load_session(env)
        data = unpacked_cookie_data(env)
        data = persistent_session_id!(data)
        [data["session_id"], data]
      end

      def extract_session_id(env)
        unpacked_cookie_data(env)["session_id"]
      end

      def unpacked_cookie_data(env)
        env["rack.session.unpacked_cookie_data"] ||= begin
          request = Rack::Request.new(env)
          session_data = request.cookies[@key]

          if @secrets.size > 0 && session_data
            session_data, digest = session_data.split("--")

            if session_data && digest
              ok = @secrets.any? do |secret|
                secret && digest == generate_hmac(session_data, secret)
              end
            end

            session_data = nil unless ok
          end

          coder.decode(session_data) || {}
        end
      end

      def persistent_session_id!(data, sid=nil)
        data ||= {}
        data["session_id"] ||= sid || generate_sid
        data
      end

      # Overwrite set cookie to bypass content equality and always stream the cookie.

      def set_cookie(env, headers, cookie)
        Utils.set_cookie_header!(headers, @key, cookie)
      end

      def set_session(env, session_id, session, options)
        session = session.merge("session_id" => session_id)
        session_data = coder.encode(session)

        if @secrets.first
          session_data = "#{session_data}--#{generate_hmac(session_data, @secrets.first)}"
        end

        if session_data.size > (4096 - @key.size)
          env["rack.errors"].puts("Warning! Rack::Session::Cookie data size exceeds 4K.")
          nil
        else
          session_data
        end
      end

      def destroy_session(env, session_id, options)
        # Nothing to do here, data is in the client
        generate_sid unless options[:drop]
      end

      def generate_hmac(data, secret)
        OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, secret, data)
      end

    end
  end
end
