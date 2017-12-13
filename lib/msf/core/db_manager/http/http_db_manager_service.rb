require 'rack'
require 'msf/core/db_manager/http/sinatra_app'
require 'metasploit/framework/parsed_options/remote_db'

class HttpDBManagerService

  def start(opts)
    parsed_options = Metasploit::Framework::ParsedOptions::RemoteDB.new
    if (parsed_options.options.database.no_signal)
      puts 'removing trap'
      opts[:signals] = false
      @shutdown_on_interupt = false
    else
      @shutdown_on_interupt = true
    end

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

    Rack::Handler::Thin.run(SinatraApp, opts) do |server|

      # TODO: prevent accidental shutdown from msfconle eg: ctrl-c
      [:INT, :TERM].each { |sig|
        trap(sig) {
          server.stop if (@shutdown_on_interupt || sig == :TERM)
        }
      }

      if opts[:ssl] && opts[:ssl] = true
        puts "Starting in HTTPS mode"
        server.ssl = true
        server.ssl_options = opts[:ssl_opts]
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