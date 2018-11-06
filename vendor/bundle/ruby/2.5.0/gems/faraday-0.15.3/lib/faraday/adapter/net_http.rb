begin
  require 'net/https'
rescue LoadError
  warn "Warning: no such file to load -- net/https. Make sure openssl is installed if you want ssl support"
  require 'net/http'
end
require 'zlib'

module Faraday
  class Adapter
    class NetHttp < Faraday::Adapter
      NET_HTTP_EXCEPTIONS = [
        IOError,
        Errno::ECONNABORTED,
        Errno::ECONNREFUSED,
        Errno::ECONNRESET,
        Errno::EHOSTUNREACH,
        Errno::EINVAL,
        Errno::ENETUNREACH,
        Errno::EPIPE,
        Net::HTTPBadResponse,
        Net::HTTPHeaderSyntaxError,
        Net::ProtocolError,
        SocketError,
        Zlib::GzipFile::Error,
      ]

      NET_HTTP_EXCEPTIONS << OpenSSL::SSL::SSLError if defined?(OpenSSL)
      NET_HTTP_EXCEPTIONS << Net::OpenTimeout if defined?(Net::OpenTimeout)

      def initialize(app = nil, opts = {}, &block)
        @cert_store = nil
        super(app, opts, &block)
      end

      def call(env)
        super
        with_net_http_connection(env) do |http|
          configure_ssl(http, env[:ssl]) if env[:url].scheme == 'https' and env[:ssl]
          configure_request(http, env[:request])

          begin
            http_response = perform_request(http, env)
          rescue *NET_HTTP_EXCEPTIONS => err
            if defined?(OpenSSL) && OpenSSL::SSL::SSLError === err
              raise Faraday::SSLError, err
            else
              raise Error::ConnectionFailed, err
            end
          end

          save_response(env, http_response.code.to_i, http_response.body || '', nil, http_response.message) do |response_headers|
            http_response.each_header do |key, value|
              response_headers[key] = value
            end
          end
        end

        @app.call env
      rescue Timeout::Error, Errno::ETIMEDOUT => err
        raise Faraday::Error::TimeoutError, err
      end

      private

      def create_request(env)
        request = Net::HTTPGenericRequest.new \
          env[:method].to_s.upcase,    # request method
          !!env[:body],                # is there request body
          :head != env[:method],       # is there response body
          env[:url].request_uri,       # request uri path
          env[:request_headers]        # request headers

        if env[:body].respond_to?(:read)
          request.body_stream = env[:body]
        else
          request.body = env[:body]
        end
        request
      end

      def perform_request(http, env)
        if :get == env[:method] and !env[:body]
          # prefer `get` to `request` because the former handles gzip (ruby 1.9)
          http.get env[:url].request_uri, env[:request_headers]
        else
          http.request create_request(env)
        end
      end

      def with_net_http_connection(env)
        yield net_http_connection(env)
      end

      def net_http_connection(env)
        if proxy = env[:request][:proxy]
          Net::HTTP::Proxy(proxy[:uri].hostname, proxy[:uri].port, proxy[:user], proxy[:password])
        else
          Net::HTTP
        end.new(env[:url].hostname, env[:url].port || (env[:url].scheme == 'https' ? 443 : 80))
      end

      def configure_ssl(http, ssl)
        http.use_ssl      = true
        http.verify_mode  = ssl_verify_mode(ssl)
        http.cert_store   = ssl_cert_store(ssl)

        http.cert         = ssl[:client_cert]  if ssl[:client_cert]
        http.key          = ssl[:client_key]   if ssl[:client_key]
        http.ca_file      = ssl[:ca_file]      if ssl[:ca_file]
        http.ca_path      = ssl[:ca_path]      if ssl[:ca_path]
        http.verify_depth = ssl[:verify_depth] if ssl[:verify_depth]
        http.ssl_version  = ssl[:version]      if ssl[:version]
        http.min_version  = ssl[:min_version]  if ssl[:min_version]
        http.max_version  = ssl[:max_version]  if ssl[:max_version]
      end

      def configure_request(http, req)
        if req[:timeout]
          http.read_timeout  = req[:timeout]
          http.open_timeout  = req[:timeout]
          http.write_timeout = req[:timeout] if http.respond_to?(:write_timeout=)
        end
        http.open_timeout  = req[:open_timeout]  if req[:open_timeout]
        http.write_timeout = req[:write_timeout] if req[:write_timeout] && http.respond_to?(:write_timeout=)
          # Only set if Net::Http supports it, since Ruby 2.5.
        http.max_retries  = 0                    if http.respond_to?(:max_retries=)

        @config_block.call(http) if @config_block
      end

      def ssl_cert_store(ssl)
        return ssl[:cert_store] if ssl[:cert_store]
        return @cert_store if @cert_store
        # Use the default cert store by default, i.e. system ca certs
        @cert_store = OpenSSL::X509::Store.new
        @cert_store.set_default_paths
        @cert_store
      end

      def ssl_verify_mode(ssl)
        ssl[:verify_mode] || begin
          if ssl.fetch(:verify, true)
            OpenSSL::SSL::VERIFY_PEER
          else
            OpenSSL::SSL::VERIFY_NONE
          end
        end
      end
    end
  end
end
