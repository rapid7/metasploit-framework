# -*- coding: binary -*-

require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'
require 'metasploit/framework/tcp/client'

module Metasploit
  module Framework
    module LoginScanner
      class X3

        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LoginScanner::RexSocket
        include Metasploit::Framework::Tcp::Client

        DEFAULT_PORT = 1818
        REALM_KEY = nil

        def encrypt_pass(inp)
          # check if it's already encrypted
          return inp if inp.start_with?('CRYPT:')

          num2 = inp.length
          num = 17
          ret = ''
          charset0 = 'cromanwqxfzpgedkvstjhyilu'.chars
          xyz = 'zxWyZxzvwYzxZXxxZWWyWxYXz'.chars
          charset1 = 'cf2tln3yuVkDr7oPaQ8bsSd4x'.chars

          (0..num2 - 1).each do |i|
            num5 = inp[i].ord
            num7 = num5.to_f / num
            num10 = (num5 % num)
            num11 = xyz[i].ord
            num12 = num11 - num7
            num12 += 1 if num12.to_i != num12
            ret << num12.to_i.chr
            ret << charset0[num10].ord.chr
            off = charset0.find_index(ret.split('').to_a[-1])
            ret << charset1[off].ord.chr if (off & 1).zero?
          end

          "CRYPT:#{ret}"
        end

        def attempt_login(credential)
          result_options = {
            credential: credential,
            status: Metasploit::Model::Login::Status::INCORRECT,
            host: host,
            port: port,
            protocol: 'tcp',
            service_name: 'X3 AdxAdmin'
          }

          # encrypt the password
          enc_pass = encrypt_pass(credential.private.to_s)
          # building the initial authentication packet
          # [2bytes][userlen 1 byte][username][userlen 1 byte][username][passlen 1 byte][CRYPT:HASH]
          user = credential.public.to_s

          t_auth_buffer = [user.length].pack('c')
          t_auth_buffer << user
          t_auth_buffer << user.length
          t_auth_buffer << user
          t_auth_buffer << enc_pass.length
          t_auth_buffer << enc_pass

          auth_buffer = "\x6a"
          auth_buffer << t_auth_buffer.length
          auth_buffer << t_auth_buffer

          begin
            connect
            select([sock], nil, nil, 0.4)

            if enc_pass
              sock.put(auth_buffer)
              result_options[:proof] = sock.get_once(1024, 2)

              if result_options[:proof] && result_options[:proof].length == 4 && (result_options[:proof].chars != [
                "\xFF", "\xFF", "\xFF", "\xFF"
              ])
                result_options[:status] = Metasploit::Model::Login::Status::SUCCESSFUL
              end
            end
          rescue Rex::ConnectionError, EOFError, Timeout::Error, Errno::EPIPE => e
            result_options.merge!(
              proof: e,
              status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
            )
          end

          disconnect if sock

          Result.new(result_options)
        end

        private

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          self.connection_timeout ||= 5
          self.port ||= DEFAULT_PORT
        end

      end
    end
  end
end
