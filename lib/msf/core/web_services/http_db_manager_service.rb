require 'rack'
# Rails 8.0 upgrade: migrated from Rack::Handler::Thin to Rack::Handler::Puma.
# Thin only supports Rack 2.x and cannot run under Rack 3.x (required by Rails 8).
# Puma was already a runtime dependency and is Rack 3-compatible.
require 'rack/handler/puma'
require 'metasploit/framework/parsed_options/remote_db'

# TODO: This functionality isn't fully used currently, it should be integrated and called from the top level msfdb.rb file
class Msf::WebServices::HttpDBManagerService

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

  # Rails 8.0 upgrade: replaced Thin server startup with Puma.
  # Thin configured SSL via server.ssl / server.ssl_options in a block callback.
  # Puma uses a URI-based SSL config (ssl://host:port?key=...&cert=...&verify_mode=...)
  # passed through the Host option, so the SSL setup was rewritten accordingly.
  def start_http_server(opts)
    host = opts[:Host] || '0.0.0.0'
    port = opts[:Port] || 8080

    puma_opts = {
      Host: host,
      Port: port,
      Threads: '0:16',
      Verbose: false,
      Silent: opts[:Silent] || false
    }

    if opts[:ssl]
      print_good('SSL Enabled')
      ssl_opts = opts[:ssl_opts] || {}
      key = ssl_opts[:private_key_file]
      cert = ssl_opts[:cert_chain_file]
      verify = ssl_opts[:verify_peer] ? 'peer' : 'none'

      ssl_uri = "ssl://#{host}:#{port}?key=#{key}&cert=#{cert}&verify_mode=#{verify}"
      puma_opts[:Host] = ssl_uri
      puma_opts.delete(:Port)
    else
      print_warning('SSL Disabled')
    end

    Rack::Handler::Puma.run(Msf::WebServices::MetasploitApiApp, **puma_opts)
  end

  def init_db
    Msf::WebServices::DBManagerProxy.instance
  end

  def require_environment!(parsed_options)
    # RAILS_ENV must be set before requiring 'config/application.rb'
    parsed_options.environment!
    ARGV.replace(parsed_options.positional)

    # allow other Rails::Applications to use this command
    if !defined?(Rails) || Rails.application.nil?
      # @see https://github.com/rails/rails/blob/v3.2.17/railties/lib/rails/commands.rb#L39-L40
      require Pathname.new(__FILE__).parent.parent.parent.parent.parent.join('config', 'application')
    end

    # have to configure before requiring environment because
    # config/environment.rb calls initialize! and the initializers will use
    # the configuration from the parsed options.
    parsed_options.configure(Rails.application)

    Rails.application.require_environment!
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


end

$console_printer = Rex::Ui::Text::Output::Stdio.new
