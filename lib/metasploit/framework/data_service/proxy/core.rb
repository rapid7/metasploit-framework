require 'singleton'
require 'open3'
require 'rex/ui'
require 'rex/logging'
require 'msf/core/db_manager'
require 'metasploit/framework/data_service/remote/http/core'
require 'metasploit/framework/data_service/remote/http/remote_service_endpoint'
require 'metasploit/framework/data_service/proxy/data_proxy_auto_loader'

#
# Holds references to data services (@see Metasploit::Framework::DataService)
# and forwards data to the implementation set as current.
#
module Metasploit
module Framework
module DataService
class DataProxy
  include Singleton
  include DataProxyAutoLoader

  attr_reader :usable

  #
  # Returns current error state
  #
  def error
    return @error if (@error)
    return @data_service.error if @data_service
    return "none"
  end

  def is_local?
    if (@data_service)
      return (@data_service.name == 'local_db_service')
    end

    return false
  end

  #
  # Determines if the data service is active
  #
  def active
    if (@data_service)
      return @data_service.active
    end

    return false
  end

  #
  # Initializes the data service to be used - primarily on startup
  #
  def init(framework, opts)
    @mutex.synchronize {
      if (@initialized)
        return
      end

      begin
        if (opts['DisableDatabase'])
          @error = 'disabled'
          return
        elsif (opts['DatabaseRemoteProcess'])
          run_remote_db_process(opts)
        else
          run_local_db_process(framework, opts)
        end
        @usable = true
        @initialized = true
      rescue Exception => e
        puts "Unable to initialize a dataservice #{e.message}"
        return
      end
    }

  end

  #
  # Registers a data service with the proxy and immediately
  # set as primary if online
  #
  def register_data_service(data_service, online=false)
    validate(data_service)

    puts "Registering data service: #{data_service.name}"
    data_service_id = @data_service_id += 1
    @data_services[data_service_id] = data_service
    set_data_service(data_service_id, online)
  end

  #
  # Set the data service to be used
  #
  def set_data_service(data_service_id, online=false)
    data_service = @data_services[data_service_id.to_i]
    if (data_service.nil?)
      puts "Data service with id: #{data_service_id} does not exist"
      return nil
    end

    if (!online && !data_service.active)
      puts "Data service not online: #{data_service.name}, not setting as active"
      return nil
    end

    puts "Setting active data service: #{data_service.name}"
    @data_service = data_service
  end

  #
  # Prints out a list of the current data services
  #
  def print_data_services()
    @data_services.each_key {|key|
      out = "id: #{key}, description: #{@data_services[key].name}"
      if (!@data_service.nil? && @data_services[key].name == @data_service.name)
        out += " [active]"
      end
      puts out  #hahaha
    }
  end

  #
  # Used to bridge the local db
  #
  def method_missing(method, *args, &block)
    #puts "Attempting to delegate method: #{method}"
    unless @data_service.nil?
      @data_service.send(method, *args, &block)
    end
  end

  #
  # Attempt to shutdown the local db process if it exists
  #
  def exit_called
    if @pid
      puts 'Killing db process'
      begin
        Process.kill("TERM", @pid)
      rescue Exception => e
        puts "Unable to kill db process: #{e.message}"
      end
    end
  end

  #########
  protected
  #########

  def get_data_service
    raise 'No registered data_service' unless @data_service
    return @data_service
  end

  #######
  private
  #######

  def initialize
    @data_services = {}
    @data_service_id = 0
    @usable = false
    @initialized = false
    @mutex = Mutex.new()
  end

  def validate(data_service)
    raise "Invalid data_service: #{data_service.class}, not of type Metasploit::Framework::DataService" unless data_service.is_a? (Metasploit::Framework::DataService)
    raise 'Cannot register null data service data_service' unless data_service
    raise 'Data Service already exists' if data_service_exist?(data_service)
  end

  def data_service_exist?(data_service)
    @data_services.each_value{|value|
      if (value.name == data_service.name)
        return true
      end
    }

    return false
  end


  def run_local_db_process(framework, opts)
    puts 'Initializing local db process'
    db_manager = Msf::DBManager.new(framework)
    if (db_manager.usable and not opts['SkipDatabaseInit'])
        register_data_service(db_manager, true)
        db_manager.init_db(opts)
    end
  end

  def run_remote_db_process(opts)
    # started with no signal to prevent ctrl-c from taking out db
    db_script = File.join( Msf::Config.install_root, "msfdb -ns")
    wait_t = Open3.pipeline_start(db_script)
    @pid = wait_t[0].pid
    puts "Started process with pid #{@pid}"

    endpoint = Metasploit::Framework::DataService::RemoteServiceEndpoint.new('localhost', 8080)
    remote_host_data_service = Metasploit::Framework::DataService::RemoteHTTPDataService.new(endpoint)
    register_data_service(remote_host_data_service, true)
  end

end
end
end
end
