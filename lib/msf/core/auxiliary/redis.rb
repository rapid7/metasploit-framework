# -*- coding: binary -*-
require 'msf/core/exploit'
module Msf
  ###
  #
  # This module provides methods for working with redis
  #
  ###
  module Auxiliary::Redis
    include Msf::Exploit::Remote::Tcp
    include Auxiliary::Scanner
    include Auxiliary::Report

    #
    # Initializes an instance of an auxiliary module that interacts with Redis
    #

    def initialize(info = {})
      super
      register_options(
        [
          Opt::RPORT(6379),
          OptString.new('PASSWORD', [false, 'Redis password for authentication test', 'foobared'])
        ]
      )

      register_advanced_options(
        [
          OptInt.new('READ_TIMEOUT', [true, 'Seconds to wait while reading redis responses', 2])
        ]
      )
    end

    def read_timeout
      datastore['READ_TIMEOUT']
    end

    def report_redis(version)
      report_service(
        host: rhost,
        port: rport,
        proto: 'tcp',
        name: 'redis',
        info: "version #{version}"
      )
    end

    def redis_command(*commands)
      command_string = printable_redis_response(commands.join(' '))
      unless (command_response = send_redis_command(*commands))
        vprint_error("No response to '#{command_string}'")
        return
      end
      if /(?<auth_response>ERR operation not permitted|NOAUTH Authentication required)/i =~ command_response
        fail_with(::Msf::Module::Failure::BadConfig, "#{peer} requires authentication but Password unset") unless datastore['Password']
        vprint_status("Requires authentication (#{printable_redis_response(auth_response, false)})")
        if (auth_response = send_redis_command('AUTH', datastore['PASSWORD']))
          unless auth_response =~ /\+OK/
            vprint_error("Authentication failure: #{printable_redis_response(auth_response)}")
            return
          end
          vprint_status("Authenticated")
          unless (command_response = send_redis_command(*commands))
            vprint_error("No response to '#{command_string}'")
            return
          end
        else
          vprint_status("Authentication failed; no response")
          return
        end
      end

      vprint_status("Redis command '#{command_string}' got '#{printable_redis_response(command_response)}'")
      command_response
    end

    def printable_redis_response(response_data, convert_whitespace = true)
      Rex::Text.ascii_safe_hex(response_data, convert_whitespace)
    end

    private

    def redis_proto(command_parts)
      return if command_parts.blank?
      command = "*#{command_parts.length}\r\n"
      command_parts.each do |c|
        command << "$#{c.length}\r\n#{c}\r\n"
      end
      command
    end

    def send_redis_command(*command_parts)
      sock.put(redis_proto(command_parts))
      command_response = sock.get_once(-1, read_timeout)
      return unless command_response
      command_response.strip
    end
  end
end
