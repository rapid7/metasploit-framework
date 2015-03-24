require 'uri'

module Msf

class Plugin::HTTPRequests < Msf::Plugin

  class ConsoleCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    def name
      'HTTP Requests'
    end

    def commands
      {
        'httpr' => 'Make an HTTP request'
      }
    end

    def parse_args(args)
      help_line = 'Usage: httpr [options] uri'
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
        '-X' => [ true,  'Request method to use' ]
      )

      options = {
        :auth_password   => nil,
        :auth_username   => nil,
        :headers         => { },
        :print_body      => true,
        :print_headers   => false,
        :method          => nil,
        :output_file     => nil,
        :ssl_version     => 'Auto',
        :uri             => nil,
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
          print_line(help_line)
          print_line(opt_parser.usage)
          return
        when '-H'
          name, _, value = val.partition(':')
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
          val = val.partition(':')
          options[:auth_username] = val[0]
          options[:auth_password] = val[2]
        when '-X'
          options[:method] = val
        else
          options[:uri] = val
        end
      end

      if options[:uri].nil?
        print_line(help_line)
        print_line(opt_parser.usage)
        return
      end

      options[:method] ||= 'GET'
      options[:uri] = URI(options[:uri])
      options
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

    def cmd_httpr(*args)
      opts = parse_args(args)
      return unless opts

      unless opts[:output_file].nil?
        begin
          opts[:output_file] = File.new(opts[:output_file], 'w')
        rescue ::Errno::EACCES, Errno::EISDIR, Errno::ENOTDIR
          print_error('Failed to open the specified file for output')
          return
        end
      end

      uri = opts[:uri]
      http_client = Rex::Proto::Http::Client.new(
        uri.host,
        uri.port,
        {'Msf' => framework},
        uri.scheme == 'https',
        opts[:ssl_version]
      )

      unless opts[:auth_username].nil?
        auth_str = opts[:auth_username].to_s + ':' + opts[:auth_password].to_s
        auth_str = 'Basic ' + Rex::Text.encode_base64(auth_str)
        opts[:headers]['Authorization'] = auth_str
      end

      uri.path = '/' if uri.path.length == 0

      begin
        http_client.connect
        request = http_client.request_cgi(
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

        response = http_client.send_recv(request)
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
        opts[:output_file].close unless opts[:output_file].nil?
        return
      end

      if opts[:print_headers]
        output_line(opts, response.cmd_string)
        output_line(opts, response.headers.to_s)
      end

      output_line(opts, response.body) if opts[:print_body]
      unless opts[:output_file].nil?
        print_status("Wrote #{opts[:output_file].tell} bytes to #{opts[:output_file].path}")
        opts[:output_file].close
      end
    end
  end

  def initialize(framework, opts)
    super
    add_console_dispatcher(ConsoleCommandDispatcher)
  end

  def cleanup
    remove_console_dispatcher('HTTP Requests')
  end

  def name
    'HTTP Requests'
  end

  def desc
    'Make HTTP requests from within Metasploit.'
  end

protected
end

end
