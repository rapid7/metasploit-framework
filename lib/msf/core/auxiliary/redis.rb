# -*- coding: binary -*-
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

    REDIS_UNAUTHORIZED_RESPONSE = /(?<auth_response>ERR operation not permitted|NOAUTH Authentication required)/i

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
      if match = command_response.match(REDIS_UNAUTHORIZED_RESPONSE)
        auth_response = match[:auth_response]
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

    def parse_redis_response(response)
      parser = RESPParser.new(response)
      parser.parse
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
      command_response = sock.get(read_timeout)
      return unless command_response
      command_response.strip
    end

    class RESPParser

      LINE_BREAK = "\r\n"

      def initialize(data)
        @raw_data = data
        @counter = 0
      end
    
      def parse
        @counter = 0
        parse_next
      end
    
      def data_at_counter
        @raw_data[@counter..-1]
      end
    
      def parse_resp_array
        # Read array length
        unless /\A\*(?<arr_len>\d+)(\r|$)/ =~ data_at_counter
          raise "RESP parsing error in array"
        end

        @counter += (1 + arr_len.length)

        if data_at_counter.start_with?(LINE_BREAK)
          @counter += LINE_BREAK.length
        end
    
        arr_len = arr_len.to_i
    
        result = []
        for index in 1..arr_len do
          element = parse_next
          result.append(element)
        end
        result
      end
    
      def parse_simple_string
        str_end = data_at_counter.index(LINE_BREAK)
        str_end = str_end.to_i
        result = data_at_counter[1..str_end - 1]
        @counter += str_end
        @counter += 2 # Skip over next CLRF
        result
      end
    
      def parse_bulk_string
        unless /\A\$(?<str_len>[-\d]+)(\r|$)/ =~ data_at_counter
          raise "RESP parsing error in bulk string"
        end

        @counter += (1 + str_len.length)
        str_len = str_len.to_i

        if data_at_counter.start_with?(LINE_BREAK)
          @counter += LINE_BREAK.length
        end

        result = nil
        if str_len != -1
          result = data_at_counter[0..str_len - 1]
          @counter += str_len
          @counter += 2 # Skip over next CLRF
        end
        result
      end
    
    
      def parse_next
        case data_at_counter[0]
        when "*"
          parse_resp_array
        when "+"
          parse_simple_string
        when "$"
          parse_bulk_string
        else
          raise "RESP parsing error: " + data_at_counter
        end
      end
    end
  end
end
