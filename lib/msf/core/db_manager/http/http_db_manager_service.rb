require 'rack'
require 'msf/core/db_manager/http/metasploit_api_app'
require 'metasploit/framework/parsed_options/remote_db'
require 'rex/ui/text/output/stdio'

class HttpDBManagerService

  def start(opts)
    parsed_options = Metasploit::Framework::ParsedOptions::RemoteDB.new
    require_environment!(parsed_options)

    if opts[:ssl]
      ssl_opts = {}
      ssl_opts[:private_key_file] = opts[:ssl_key]
      ssl_opts[:cert_chain_file] = opts[:ssl_cert]
      ssl_opts[:verify_peer] = false
      opts[:ssl] = true
      opts[:ssl_opts] = ssl_opts
    end

    init_db
    start_http_server(opts)
  end

  private

  def start_http_server(opts)

    Rack::Handler::Thin.run(MetasploitApiApp, opts) do |server|

      if opts[:ssl] && opts[:ssl] = true
        print_good('SSL Enabled')
        server.ssl = true
        server.ssl_options = opts[:ssl_opts]
      else
        print_warning('SSL Disabled')
      end
      server.threaded = true
    end
  end

  def init_db
    DBManagerProxy.instance
  end

  def require_environment!(parsed_options)
    # RAILS_ENV must be set before requiring 'config/application.rb'
    parsed_options.environment!
    ARGV.replace(parsed_options.positional)

    # allow other Rails::Applications to use this command
    if !defined?(Rails) || Rails.application.nil?
      # @see https://github.com/rails/rails/blob/v3.2.17/railties/lib/rails/commands.rb#L39-L40
      require Pathname.new(__FILE__).parent.parent.parent.parent.parent.parent.join('config', 'application')
    end

    # have to configure before requiring environment because
    # config/environment.rb calls initialize! and the initializers will use
    # the configuration from the parsed options.
    parsed_options.configure(Rails.application)

    Rails.application.require_environment!
  end

  # def init_servlets(http_server)
  #   servlet_path = File.dirname(__FILE__) + '/servlet/*'
  #   Dir.glob(servlet_path).collect{|file_path|
  #     servlet_class = File.basename(file_path, '.rb').classify
  #     require file_path
  #     servlet_class_constant = servlet_class.constantize
  #     http_server.mount servlet_class_constant.api_path, servlet_class_constant
  #   }
  # end



end


def print_line(msg)
  $console_printer.print_line(msg)
end

def print_warning(msg)
  $console_printer.print_warning(msg)
end

def print_good(msg)
  $console_printer.print_good(msg)
end

def print_error(msg, exception = nil)
  unless exception.nil?
    msg += "\n    Call Stack:"
    exception.backtrace.each {|line|
      msg += "\n"
      msg += "\t #{line}"
    }
  end

  $console_printer.print_error(msg)
end

$console_printer = Rex::Ui::Text::Output::Stdio.new
