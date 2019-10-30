require 'open3'
require 'rex/ui'
require 'rex/logging'
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
  # Registers the specified data service with the proxy
  # and immediately sets it as the primary if active
  #
  def register_data_service(data_service)
    validate(data_service)
    data_service_id = @data_service_id += 1
    @data_services[data_service_id] = data_service
    set_data_service(data_service_id)
  end

  #
  # Delete the specified data service
  #
  def delete_data_service(data_service_id)
    raise ArgumentError.new('Cannot delete data service id: 1') if data_service_id.to_i == 1

    data_service = @data_services.delete(data_service_id.to_i)
    if data_service.nil?
      raise "Data service with id: #{data_service_id} does not exist"
    end

    if @current_data_service == data_service
      # set the current data service to the first data service created
      @current_data_service = @data_services[1]
    end
  end

  def delete_current_data_service
    @data_services.each do |id, ds|
      if ds == @current_data_service
        if id == 1
          raise "Unable to delete the local data service. Please use db_disconnect."
        else
          @data_services.delete(id)
          @current_data_service = @data_services[1]
        end
      end
    end
  end

  #
  # Set the data service to be used
  #
  def set_data_service(data_service_id)
    data_service = @data_services[data_service_id.to_i]
    if data_service.nil?
      raise "Data service with id: #{data_service_id} does not exist"
    end

    if !data_service.is_local? && !data_service.active
      raise "Data service #{data_service.name} is not online, and won't be set as active"
    end

    prev_data_service = @current_data_service
    @current_data_service = data_service
    # reset the previous data service's active flag if it is remote
    # to ensure checks are performed the next time it is set
    if !prev_data_service.nil? && !prev_data_service.is_local?
      prev_data_service.active = false
    end
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

  # Performs a set of data service operations declared within the block.
  # This passes the @current_data_service as a parameter to the block.
  # If there is no current data service registered or the data service
  # is not active, the block is not executed and the method simply returns.
  def data_service_operation(&block)
    return unless block_given?

    begin
      data_service = self.get_data_service
    rescue
      return
    end

    block.call(data_service) if !data_service.nil? && self.active
  end

  def log_error(exception, ui_message)
    elog "#{ui_message}: #{exception.message}"
    exception.backtrace.each { |line| elog "#{line}" }
    # TODO: We should try to surface the original exception, instead of just a generic one.
    # This should not display the full backtrace, only the message.
    raise exception
  end

  # Adds a valid workspace value to the opts hash before sending on to the data layer.
  #
  # @param [Hash] opts The opts hash that will be passed to the data layer.
  # @param [String] wspace A specific workspace name to add to the opts hash.
  # @return [Hash] The opts hash with a valid :workspace value added.
  def add_opts_workspace(opts, wspace = nil)
    # If :id is present the user only wants a specific record, so workspace isn't needed
    return if opts.key?(:id)

    # Some methods use the key :wspace. Let's standardize on :workspace and clean it up here.
    opts[:workspace] = opts.delete(:wspace) unless opts[:wspace].nil?

    # If the user passed in a specific workspace then use that in opts
    opts[:workspace] = wspace if wspace

    # We only want to pass the workspace name, so grab it if it is currently an object.
    if opts[:workspace] && opts[:workspace].is_a?(::Mdm::Workspace)
      opts[:workspace] = opts[:workspace].name
    end

    # If we still don't have a :workspace value, just set it to the current workspace.
    opts[:workspace] = workspace.name if opts[:workspace].nil?

    opts
  end

  #######
  private
  #######

  def setup(opts)
    begin
      db_manager = opts.delete(:db_manager)
      if !db_manager.nil?
        register_data_service(db_manager)
        @usable = true
      else
        @error = 'disabled'
      end
    rescue => e
      @error = e
      raise "Unable to initialize data service: #{e.message}"
    end
  end

  def validate(data_service)
    raise "Invalid data_service: #{data_service.class}, not of type Metasploit::Framework::DataService" unless data_service.is_a? (Metasploit::Framework::DataService)
    raise 'Cannot register null data service data_service' unless data_service
    raise 'Data Service already exists' if data_service_exist?(data_service)
    # Raising an error for local DB causes startup to fail if there is a DB configured but we are unable to connect
    # TODO: The check here shouldn't be dependent on if the data_service is local or not. We shouldn't
    # connect to any data service if it is not online/active. This can likely be fixed by making a true
    # LocalDataService instead of using DBManager.
    unless data_service.is_local?
      raise 'Data Service does not appear to be responding' unless data_service.active
    end
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
