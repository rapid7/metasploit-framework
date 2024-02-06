require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'
require 'rex/proto/amqp'

module Metasploit
  module Framework
    module LoginScanner

      class AMQP
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LoginScanner::RexSocket

        DEFAULT_PORT         = 5671
        LIKELY_PORTS         = [ DEFAULT_PORT, 5672 ]
        LIKELY_SERVICE_NAMES = [ 'amqp', 'amqps' ]
        PRIVATE_TYPES        = [ :password ]
        REALM_KEY           = nil

        # (see Base#attempt_login)
        def attempt_login(credential)
          result_options = {
              credential: credential
          }

          begin
            result_options.merge!(connect_login(credential.public, credential.private))
          rescue Rex::Proto::Amqp::Error::NegotiationError => e
            result_options[:status] = Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
            result_options[:proof] = e.message
          rescue Rex::Proto::Amqp::Error::AmqpError
            result_options[:status] = Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
          rescue ::EOFError, Errno::ECONNRESET, Rex::ConnectionError, Rex::ConnectionTimeout, ::Timeout::Error
            result_options[:status] = Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
          end

          result = ::Metasploit::Framework::LoginScanner::Result.new(result_options)
          result.host         = host
          result.port         = port
          result.protocol     = 'tcp'
          result.service_name = "amqp#{ssl ? 's' : ''}"
          result
        end

        private

        def connect_login(username, password)
          result = {}
          amqp_client = Rex::Proto::Amqp::Version091::Client.new(
            host,
            port: port,
            context: { 'Msf' => framework, 'MsfExploit' => framework_module },
            ssl: ssl,
            ssl_version: ssl_version
          )
          amqp_client.connect(connection_timeout)
          amqp_client.send_protocol_header
          amqp_client.connection_start(username, password)
          resp = amqp_client.recv_frame

          unless resp.is_a?(Rex::Proto::Amqp::Version091::Frames::AmqpVersion091MethodFrame)
            raise Rex::Proto::Amqp::Error::UnexpectedReplyError.new(resp)
          end

          if resp.class_id == Rex::Proto::Amqp::Version091::Frames::MethodArguments::AmqpVersion091ConnectionClose::CLASS_ID && \
              resp.method_id == Rex::Proto::Amqp::Version091::Frames::MethodArguments::AmqpVersion091ConnectionClose::METHOD_ID
            result[:status] = Metasploit::Model::Login::Status::INCORRECT
            result[:proof] = resp.arguments.reply_text
            return result
          end

          unless resp.class_id == Rex::Proto::Amqp::Version091::Frames::MethodArguments::AmqpVersion091ConnectionTune::CLASS_ID && \
              resp.method_id == Rex::Proto::Amqp::Version091::Frames::MethodArguments::AmqpVersion091ConnectionTune::METHOD_ID
            raise Rex::Proto::Amqp::Error::UnexpectedReplyError.new(resp)
          end

          result[:status] = Metasploit::Model::Login::Status::SUCCESSFUL
          result
        ensure
          amqp_client.close
        end

        def set_sane_defaults
          self.connection_timeout ||= 30
          self.port               ||= DEFAULT_PORT
        end
      end
    end
  end
end
