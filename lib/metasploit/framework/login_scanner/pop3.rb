require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'
require 'metasploit/framework/tcp/client'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with POP3.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.
      class POP3
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LoginScanner::RexSocket
        include Metasploit::Framework::Tcp::Client

        attr_accessor :sock

        # This method attempts a single login with a single credential against the target
        # @param credential [Credential] The credential object to attmpt to login with
        # @return [Metasploit::Framework::LoginScanner::Result] The LoginScanner Result object
        def attempt_login(credential)
          result_options = {
            credential: credential
          }
          begin
            disconnect if self.sock

            connect
            sleep(0.4)

            if sock.get_once[/^\+OK (.*)/]
              sock.put("USER #{credential.public}\r\n")
              if sock.get_once[/^\+OK (.*)/]
                sock.put("PASS #{credential.private}\r\n")
                result_options[:proof] = sock.get_once
                if result_options[:proof][/^\+OK (.*)/]
                  result_options[:status] = :success
                else
                  result_options[:status] = :failed
                end
              else
                result_options[:status] = :failed
              end
            else
              result_options[:status] = :failed
            end
          rescue ::Rex::ConnectionError, ::Timeout::Error, ::Errno::EPIPE

          end

          # disconnect

        end

        private

        # This method sets the sane defaults for things
        # like timeouts and TCP evasion options
        def set_sane_defaults
          self.max_send_size = 0 if self.max_send_size.nil?
          self.send_delay = 0 if self.send_delay.nil?
        end

       end

    end
  end
end
