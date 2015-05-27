require 'uri'

module Msf

class Plugin::Requests < Msf::Plugin

  class ConsoleCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    def name
      'Request'
    end

    def commands
      {
        'request' => "Make a request of the specified type (#{types.join(', ')})",
      }
    end

    def types
      # dynamically figure out what types are supported based on parse_args_*
      parse_methods = self.public_methods.select {|m| m.to_s =~ /^parse_args_/}
      parse_methods.collect {|m| m.to_s.split('_').slice(2..-1).join('_')}
    end

    def cmd_request(*args)
      # grab and validate the first arg as type, which will affect how the
      # remaining args are parsed
      type = args.shift
      # short circuit the whole deal if they need help
      return help if (!type || type =~ /^-?-h(?:elp)?$/)
      type.downcase!
      opts, opt_parser = parse_args(type, args)

      if opts && opt_parser
        # handle any "global" options
        if opts[:output_file]
          begin
            opts[:output_file] = File.new(opts[:output_file], 'w')
          rescue ::Errno::EACCES, Errno::EISDIR, Errno::ENOTDIR
            return help(opt_parser, 'Failed to open the specified file for output')
          end
        end
        # hand off the actual request to the appropriate request handler
        handler_method = "handle_request_#{type}".to_sym
        if self.respond_to?(handler_method)
          # call the appropriate request handler
          self.send(handler_method, opts, opt_parser)
        else
          help(opt_parser, "No request handler found for type (#{type.to_s}).")
        end
      else
        help(opt_parser, "No valid options provided for request #{type}")
      end
    end

    def parse_args(type, args)
      type.downcase!
      #print_line "type is #{type}"
      parse_method = "parse_args_#{type}".to_sym
      if self.respond_to?(parse_method)
        self.send(parse_method, args, type)
      else
        print_line('Unrecognized type.')
        help
      end
    end

    # arg parsing for requests of type 'http'
    def parse_args_http(args = [], type = 'http')
      opt_parser = Rex::Parser::Arguments.new(
        '-0' => [ false, 'Use HTTP 1.0' ],
        '-1' => [ false, 'Use TLSv1 (SSL)' ],
        '-2' => [ false, 'Use SSLv2 (SSL)' ],
        '-3' => [ false, 'Use SSLv3 (SSL)' ],
        '-A' => [ true,  'User-Agent to send to server' ],
        '-d' => [ true,  'HTTP POST data' ],
        '-G' => [ false, 'Send the -d data with an HTTP GET' ],
        '-h' => [ false, 'This help text' ],
        '-H' => [ true,  'Custom header to pass to server' ],
        '-i' => [ false, 'Include headers in the output' ],
        '-I' => [ false, 'Show document info only' ],
        '-o' => [ true,  'Write output to <file> instead of stdout' ],
        '-u' => [ true,  'Server user and password' ],
        '-X' => [ true,  'Request method to use' ],
        '-x' => [ true,  'Proxy to use, format: [proto://][user:pass@]host[:port]' +
                          '  Proto defaults to http:// and port to 1080'],
      )

      options = {
        :headers         => {},
        :print_body      => true,
        :print_headers   => false,
        :ssl_version     => 'Auto',
        :user_agent      => Rex::Proto::Http::Client::DefaultUserAgent,
        :version         => '1.1'
      }

      opt_parser.parse(args) do |opt, idx, val|
        case opt
        when '-0'
          options[:version] = '1.0'
        when '-1'
          options[:ssl_version] = 'TLS1'
        when '-2'
          options[:ssl_version] = 'SSL2'
        when '-3'
          options[:ssl_version] = 'SSL3'
        when '-A'
          options[:user_agent] = val
        when '-d'
          options[:data] = val
          options[:method] ||= 'POST'
        when '-G'
          options[:method] = 'GET'
        when '-h'
          return help(opt_parser, "Usage: request #{type} [options] uri")
        when '-H'
          name, _, value = val.split(':')
          options[:headers][name] = value.strip
        when '-i'
          options[:print_headers] = true
        when '-I'
          options[:print_headers] = true
          options[:print_body]    = false
          options[:method] ||= 'HEAD'
        when '-o'
          options[:output_file] = File.expand_path(val)
        when '-u'
          options[:auth_username] = val
        when '-p'
          options[:auth_password] = val
        when '-X'
          options[:method] = val
        #when '-x'
          # @TODO proxy
        else
          options[:uri] = val
        end
      end
      unless options[:uri]
        return help(opt_parser, "Usage: request #{type} [options] uri")
      end
      options[:method] ||= 'GET'
      options[:uri] = URI(options[:uri])
      [options, opt_parser]
    end

    # handling for requests of type 'http'
    def handle_request_http(opts, opt_parser)
      uri = opts[:uri]
      http_client = Rex::Proto::Http::Client.new(
        uri.host,
        uri.port,
        {'Msf' => framework},
        uri.scheme == 'https',
        opts[:ssl_version]
      )

      if opts[:auth_username]
        auth_str = opts[:auth_username] + ':' + opts[:auth_password]
        auth_str = 'Basic ' + Rex::Text.encode_base64(auth_str)
        opts[:headers]['Authorization'] = auth_str
      end

      uri.path = '/' if uri.path.length == 0

      begin
        http_client.connect
        req = http_client.request_cgi(
          'agent'    => opts[:user_agent],
          'data'     => opts[:data],
          'headers'  => opts[:headers],
          'method'   => opts[:method],
          'password' => opts[:auth_password],
          'query'    => uri.query,
          'uri'      => uri.path,
          'username' => opts[:auth_username],
          'version'  => opts[:version]
        )

        response = http_client.send_recv(req)
      rescue ::OpenSSL::SSL::SSLError
        print_error('Encountered an SSL error')
      rescue ::Errno::ECONNRESET => ex
        print_error('The connection was reset by the peer')
      rescue ::EOFError, Errno::ETIMEDOUT, Rex::ConnectionError, ::Timeout::Error
        print_error('Encountered an error')
      #rescue ::Exception => ex
      #  print_line("An error of type #{ex.class} happened, message is #{ex.message}")
      ensure
        http_client.close
      end

      unless response
        opts[:output_file].close if opts[:output_file]
        return nil
      end

      if opts[:print_headers]
        output_line(opts, response.cmd_string)
        output_line(opts, response.headers.to_s)
      end

      output_line(opts, response.body) if opts[:print_body]
      if opts[:output_file]
        print_status("Wrote #{opts[:output_file].tell} bytes to #{opts[:output_file].path}")
        opts[:output_file].close
      end
    end

    def output_line(opts, line)
      if opts[:output_file].nil?
        if line[-2..-1] == "\r\n"
          print_line(line[0..-3])
        elsif line[-1] == "\n"
          print_line(line[0..-2])
        else
          print_line(line)
        end
      else
        opts[:output_file].write(line)
      end
    end

    def help(opt_parser = nil, msg = 'Usage: request type [options]')
      print_line(msg)
      if opt_parser
        print_line(opt_parser.usage)
      else
        print_line("Valid types are: #{types.join(', ')}")
      end
    end

  end

  def initialize(framework, opts)
    super
    add_console_dispatcher(ConsoleCommandDispatcher)
  end

  def cleanup
    remove_console_dispatcher('Request')
  end

  def name
    'Request'
  end

  def desc
    'Make requests from within Metasploit using various protocols.'
  end

end # end class

end # end module
