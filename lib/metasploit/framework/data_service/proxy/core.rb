require 'open3'
require 'rex/ui'
require 'rex/logging'
require 'metasploit/framework/data_service/remote/http/core'
require 'metasploit/framework/data_service/proxy/data_proxy_auto_loader'

#
# Holds references to data services (@see Metasploit::Framework::DataService)
# and forwards data to the implementation set as current.
#
module Metasploit
module Framework
module DataService
class DataProxy
  include DataProxyAutoLoader

  attr_reader :usable

  def initialize(opts = {})
    @data_services = {}
    @data_service_id = 0
    @usable = false
    setup(opts)
  end

  #
  # Returns current error state
  #
  def error
    return @error if (@error)
    return @current_data_service.error if @current_data_service && !@current_data_service.error.nil?
    return 'unknown'
  end

  def is_local?
    if @current_data_service
      return @current_data_service.is_local?
    end

    return false
  end

  #
  # Determines if the data service is active
  #
  def active
    if @current_data_service
      return @current_data_service.active
    end

    return false
  end

  #
  # Registers a data service with the proxy and immediately
  # set as primary if online
  #
  def register_data_service(data_service, online=false)
    validate(data_service)
    data_service_id = @data_service_id += 1
    @data_services[data_service_id] = data_service
    set_data_service(data_service_id, online)
  end

  #
  # Set the data service to be used
  #
  def set_data_service(data_service_id, online=false)
    data_service = @data_services[data_service_id.to_i]
    if data_service.nil?
      raise "Data service with id: #{data_service_id} does not exist"
    end

    if !online && !data_service.active
      raise "Data service not online: #{data_service.name}, not setting as active"
    end

    @current_data_service = data_service
  end

  #
  # Retrieves metadata about the data services
  #
  def get_services_metadata()
    services_metadata = []
    @data_services.each_key {|key|
      name = @data_services[key].name
      active = !@current_data_service.nil? && name == @current_data_service.name
      is_local = @data_services[key].is_local?
      services_metadata << Metasploit::Framework::DataService::Metadata.new(key, name, active, is_local)
    }

    services_metadata
  end

  #
  # Used to bridge the local db
  #
  def method_missing(method, *args, &block)
    unless @current_data_service.nil?
      @current_data_service.send(method, *args, &block)
    end
  end

  def respond_to?(method_name, include_private=false)
    unless @current_data_service.nil?
      return @current_data_service.respond_to?(method_name, include_private)
    end

    false
  end

  def get_data_service
    raise 'No registered data_service' unless @current_data_service
    return @current_data_service
  end

  def log_error(exception, ui_message)
    elog "#{ui_message}: #{exception.message}"
    exception.backtrace.each { |line| elog "#{line}" }
    # TODO: We should try to surface the original exception, instead of just a generic one.
    # This should not display the full backtrace, only the message.
    raise Exception, "#{ui_message}: #{exception.message}. See log for more details."
  end

  #######
  private
  #######

  def setup(opts)
    begin
      db_manager = opts.delete(:db_manager)
      if !db_manager.nil?
        register_data_service(db_manager, true)
        @usable = true
      else
        @error = 'disabled'
      end
    rescue Exception => e
      raise "Unable to initialize data service: #{e.message}"
    end
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

end
end
end
end
