require 'rubygems'
require 'windows/error'
require 'windows/service'
require 'windows/file'
require 'windows/process'
require 'windows/security'
require 'windows/msvcrt/string'
require 'windows/msvcrt/buffer'

# The Win32 module serves as a namespace only.
module Win32

  # The Service class encapsulates services controller actions, such as
  # creating, starting, configuring or deleting services.
  class Service

    # This is the error typically raised if one of the Service methods
    # should fail for any reason.
    class Error < StandardError; end
      
    include Windows::Error
    include Windows::Service
    include Windows::File
    include Windows::Process
    include Windows::Security
    include Windows::MSVCRT::String
    include Windows::MSVCRT::Buffer
           
    extend Windows::Error
    extend Windows::Service
    extend Windows::File
    extend Windows::Process
    extend Windows::Security
    extend Windows::MSVCRT::String
    extend Windows::MSVCRT::Buffer
      
    # The version of the win32-service library
    VERSION = '0.7.2'
      
    # SCM security and access rights
      
    # Includes STANDARD_RIGHTS_REQUIRED, in addition to all other rights
    MANAGER_ALL_ACCESS = SC_MANAGER_ALL_ACCESS

    # Required to call the CreateService function
    MANAGER_CREATE_SERVICE = SC_MANAGER_CREATE_SERVICE

    # Required to connect to the service control manager.
    MANAGER_CONNECT = SC_MANAGER_CONNECT

    # Required to call the EnumServicesStatusEx function to list services
    MANAGER_ENUMERATE_SERVICE = SC_MANAGER_ENUMERATE_SERVICE

    # Required to call the LockServiceDatabase function
    MANAGER_LOCK = SC_MANAGER_LOCK

    # Required to call the NotifyBootConfigStatus function
    MANAGER_MODIFY_BOOT_CONFIG = SC_MANAGER_MODIFY_BOOT_CONFIG

    # Required to call the QueryServiceLockStatus function
    MANAGER_QUERY_LOCK_STATUS = SC_MANAGER_QUERY_LOCK_STATUS

    # Includes STANDARD_RIGHTS_REQUIRED in addition to all access rights
    ALL_ACCESS = SERVICE_ALL_ACCESS

    # Required to call functions that configure existing services
    CHANGE_CONFIG = SERVICE_CHANGE_CONFIG

    # Required to enumerate all the services dependent on the service
    ENUMERATE_DEPENDENTS = SERVICE_ENUMERATE_DEPENDENTS

    # Required to make a service report its status immediately
    INTERROGATE = SERVICE_INTERROGATE

    # Required to control a service with a pause or resume
    PAUSE_CONTINUE = SERVICE_PAUSE_CONTINUE

    # Required to be able to gather configuration information about a service
    QUERY_CONFIG = SERVICE_QUERY_CONFIG

    # Required to be ask the SCM about the status of a service
    QUERY_STATUS = SERVICE_QUERY_STATUS

    # Required to call the StartService function to start the service.
    START = SERVICE_START

    # Required to call the ControlService function to stop the service.
    STOP = SERVICE_STOP

    # Required to call ControlService with a user defined control code
    USER_DEFINED_CONTROL = SERVICE_USER_DEFINED_CONTROL
      
    # Service Types

    # Driver service
    KERNEL_DRIVER = SERVICE_KERNEL_DRIVER

    # File system driver service
    FILE_SYSTEM_DRIVER  = SERVICE_FILE_SYSTEM_DRIVER

    # Service that runs in its own process
    WIN32_OWN_PROCESS   = SERVICE_WIN32_OWN_PROCESS

    # Service that shares a process with one or more other services.
    WIN32_SHARE_PROCESS = SERVICE_WIN32_SHARE_PROCESS

    # The service can interact with the desktop
    INTERACTIVE_PROCESS = SERVICE_INTERACTIVE_PROCESS

    DRIVER = SERVICE_DRIVER
    TYPE_ALL = SERVICE_TYPE_ALL
      
    # Service start options

    # A service started automatically by the SCM during system startup
    BOOT_START = SERVICE_BOOT_START

    # A device driver started by the IoInitSystem function. Drivers only
    SYSTEM_START = SERVICE_SYSTEM_START

    # A service started automatically by the SCM during system startup
    AUTO_START = SERVICE_AUTO_START

    # A service started by the SCM when a process calls StartService
    DEMAND_START = SERVICE_DEMAND_START

    # A service that cannot be started
    DISABLED = SERVICE_DISABLED
      
    # Error control

    # Error logged, startup continues
    ERROR_IGNORE = SERVICE_ERROR_IGNORE

    # Error logged, pop up message, startup continues
    ERROR_NORMAL   = SERVICE_ERROR_NORMAL

    # Error logged, startup continues, system restarted last known good config
    ERROR_SEVERE   = SERVICE_ERROR_SEVERE

    # Error logged, startup fails, system restarted last known good config
    ERROR_CRITICAL = SERVICE_ERROR_CRITICAL
      
    # Current state
 
    # Service is not running
    STOPPED = SERVICE_STOPPED

    # Service has received a start signal but is not yet running
    START_PENDING = SERVICE_START_PENDING

    # Service has received a stop signal but is not yet stopped
    STOP_PENDING  = SERVICE_STOP_PENDING

    # Service is running
    RUNNING = SERVICE_RUNNING

    # Service has received a signal to resume but is not yet running
    CONTINUE_PENDING = SERVICE_CONTINUE_PENDING

    # Service has received a signal to pause but is not yet paused
    PAUSE_PENDING = SERVICE_PAUSE_PENDING

    # Service is paused
    PAUSED = SERVICE_PAUSED
    
    # Service controls

    # Notifies service that it should stop
    CONTROL_STOP = SERVICE_CONTROL_STOP

    # Notifies service that it should pause
    CONTROL_PAUSE = SERVICE_CONTROL_PAUSE

    # Notifies service that it should resume
    CONTROL_CONTINUE = SERVICE_CONTROL_CONTINUE

    # Notifies service that it should return its current status information
    CONTROL_INTERROGATE = SERVICE_CONTROL_INTERROGATE

    # Notifies a service that its parameters have changed
    CONTROL_PARAMCHANGE = SERVICE_CONTROL_PARAMCHANGE

    # Notifies a service that there is a new component for binding
    CONTROL_NETBINDADD = SERVICE_CONTROL_NETBINDADD

    # Notifies a service that a component for binding has been removed
    CONTROL_NETBINDREMOVE = SERVICE_CONTROL_NETBINDREMOVE

    # Notifies a service that a component for binding has been enabled
    CONTROL_NETBINDENABLE = SERVICE_CONTROL_NETBINDENABLE

    # Notifies a service that a component for binding has been disabled
    CONTROL_NETBINDDISABLE = SERVICE_CONTROL_NETBINDDISABLE

    # Failure actions

    # No action
    ACTION_NONE = SC_ACTION_NONE

    # Reboot the computer
    ACTION_REBOOT = SC_ACTION_REBOOT

    # Restart the service
    ACTION_RESTART = SC_ACTION_RESTART

    # Run a command
    ACTION_RUN_COMMAND = SC_ACTION_RUN_COMMAND
      
    # :stopdoc: #
 
    StatusStruct = Struct.new(
      'ServiceStatus',
      :service_type,
      :current_state,
      :controls_accepted,
      :win32_exit_code,
      :service_specific_exit_code,
      :check_point,
      :wait_hint,
      :interactive,
      :pid,
      :service_flags
    )

    ConfigStruct = Struct.new(
      'ServiceConfigInfo',
      :service_type,
      :start_type,
      :error_control,
      :binary_path_name,
      :load_order_group,
      :tag_id,
      :dependencies,
      :service_start_name,
      :display_name
    )
      
    ServiceStruct = Struct.new(
      'ServiceInfo',
      :service_name,
      :display_name,
      :service_type,
      :current_state,
      :controls_accepted,
      :win32_exit_code,
      :service_specific_exit_code,
      :check_point,
      :wait_hint,
      :binary_path_name,
      :start_type,
      :error_control,
      :load_order_group,
      :tag_id,
      :start_name,
      :dependencies,
      :description,
      :interactive,
      :pid,
      :service_flags,
      :reset_period,
      :reboot_message,
      :command,
      :num_actions,
      :actions
    )

    # :startdoc: #
     
    # Creates a new service with the specified +options+. A +service_name+
    # must be specified or an ArgumentError is raised. A +host+ option may
    # be specified. If no host is specified the local machine is used.
    #
    # Possible Options:
    #
    # * service_name           => nil (you must specify)
    # * host                   => nil (optional)
    # * display_name           => service_name
    # * desired_access         => Service::ALL_ACCESS
    # * service_type           => Service::WIN32_OWN_PROCESS |
    #                             Service::INTERACTIVE_PROCESS
    # * start_type             => Service::DEMAND_START
    # * error_control          => Service::ERROR_NORMAL
    # * binary_path_name       => nil
    # * load_order_group       => nil
    # * dependencies           => nil
    # * service_start_name     => nil
    # * password               => nil
    # * description            => nil
    # * failure_reset_period   => nil,
    # * failure_reboot_message => nil,
    # * failure_command        => nil,
    # * failure_actions        => nil,
    # * failure_delay          => 0
    #
    # Example:
    #
    #    # Configure everything
    #    Service.new(
    #      :service_name       => 'some_service',
    #      :host               => 'localhost',
    #      :service_type       => Service::WIN32_OWN_PROCESS,
    #      :description        => 'A custom service I wrote just for fun',
    #      :start_type         => Service::AUTO_START,
    #      :error_control      => Service::ERROR_NORMAL,
    #      :binary_path_name   => 'C:\path\to\some_service.exe',
    #      :load_order_group   => 'Network',
    #      :dependencies       => ['W32Time','Schedule'],
    #      :service_start_name => 'SomeDomain\\User',
    #      :password           => 'XXXXXXX',
    #      :display_name       => 'This is some service',
    #    )
    #
    def initialize(options={})        
      unless options.is_a?(Hash)
        raise ArgumentError, 'options parameter must be a hash'
      end

      if options.empty?
        raise ArgumentError, 'no options provided'
      end

      opts = {
        'display_name'           => nil,
        'desired_access'         => SERVICE_ALL_ACCESS,
        'service_type'           => SERVICE_WIN32_OWN_PROCESS |
                                    SERVICE_INTERACTIVE_PROCESS,
        'start_type'             => SERVICE_DEMAND_START,
        'error_control'          => SERVICE_ERROR_NORMAL,
        'binary_path_name'       => nil,
        'load_order_group'       => nil,
        'dependencies'           => nil,
        'service_start_name'     => nil,
        'password'               => nil,
        'description'            => nil,
        'failure_reset_period'   => nil,
        'failure_reboot_message' => nil,
        'failure_command'        => nil,
        'failure_actions'        => nil,
        'failure_delay'          => 0,
        'host'                   => nil,
        'service_name'           => nil            
      }

      # Validate the hash options
      options.each{ |key, value|
        key = key.to_s.downcase
        unless opts.include?(key)
          raise ArgumentError, "Invalid option '#{key}'"
        end
        opts[key] = value
      }
         
      unless opts['service_name']
        raise ArgumentError, 'No service_name specified'            
      end
         
      service_name = opts.delete('service_name')
      host = opts.delete('host')
         
      raise TypeError unless service_name.is_a?(String)
      raise TypeError if host && !host.is_a?(String)

      begin
        handle_scm = OpenSCManager(host, 0, SC_MANAGER_CREATE_SERVICE)

        if handle_scm == 0
          raise Error, get_last_error
        end
        
        # Display name defaults to service_name
        opts['display_name'] ||= service_name

        dependencies = opts['dependencies']

        if dependencies && !dependencies.empty?
          unless dependencies.is_a?(Array) || dependencies.is_a?(String)
            raise TypeError, 'dependencies must be a string or array'
          end
           
          if dependencies.is_a?(Array)
            dependencies = dependencies.join("\000")
          end
              
          dependencies += "\000"
        end

        handle_scs = CreateService(
          handle_scm,
          service_name,
          opts['display_name'],
          opts['desired_access'],
          opts['service_type'],
          opts['start_type'],
          opts['error_control'],
          opts['binary_path_name'],
          opts['load_order_group'],
          0,
          dependencies,
          opts['service_start_name'],
          opts['password']
        )

        if handle_scs == 0
          raise Error, get_last_error
        end

        if opts['description']
          description = 0.chr * 4 # sizeof(SERVICE_DESCRIPTION)
          description[0,4] = [opts['description']].pack('p*')

          bool = ChangeServiceConfig2(
            handle_scs,
            SERVICE_CONFIG_DESCRIPTION,
            description
          )

          unless bool
            raise Error, get_last_error
          end
        end
         
        if opts['failure_reset_period'] || opts['failure_reboot_message'] ||
           opts['failure_command'] || opts['failure_actions']
        then
          Service.configure_failure_actions(handle_scs, opts)
        end         
      ensure
        CloseServiceHandle(handle_scs) if handle_scs && handle_scs > 0
        CloseServiceHandle(handle_scm) if handle_scm && handle_scm > 0
      end

      self
    end

    # Configures the named +service+ on +host+, or the local host if no host
    # is specified. The +options+ parameter is a hash that can contain any
    # of the following parameters:
    #
    # * service_type
    # * start_type
    # * error_control
    # * binary_path_name
    # * load_order_group
    # * dependencies
    # * service_start_name
    # * password (used with service_start_name)
    # * display_name
    # * description
    # * failure_reset_period
    # * failure_reboot_message
    # * failure_command
    # * failure_actions
    # * failure_delay
    #
    # Examples:
    #
    #    # Configure only the display name
    #    Service.configure(
    #      :service_name => 'some_service',
    #      :display_name => 'Test 33'
    #    )
    #
    #    # Configure everything
    #    Service.configure(
    #       :service_name       => 'some_service'
    #       :service_type       => Service::WIN32_OWN_PROCESS,
    #       :start_type         => Service::AUTO_START,
    #       :error_control      => Service::ERROR_NORMAL,
    #       :binary_path_name   => 'C:\path\to\some_service.exe',
    #       :load_order_group   => 'Network',
    #       :dependencies       => ['W32Time','Schedule']
    #       :service_start_name => 'SomeDomain\\User',
    #       :password           => 'XXXXXXX',
    #       :display_name       => 'This is some service',
    #       :description        => 'A custom service I wrote just for fun'
    #    )
    #
    def self.configure(options={})    
      unless options.is_a?(Hash)
        raise ArgumentError, 'options parameter must be a hash'
      end

      if options.empty?
        raise ArgumentError, 'no options provided'
      end

      opts = {
        'service_type'           => SERVICE_NO_CHANGE,
        'start_type'             => SERVICE_NO_CHANGE,
        'error_control'          => SERVICE_NO_CHANGE,
        'binary_path_name'       => nil,
        'load_order_group'       => nil,
        'dependencies'           => nil,
        'service_start_name'     => nil,
        'password'               => nil,
        'display_name'           => nil,
        'description'            => nil,
        'failure_reset_period'   => nil,
        'failure_reboot_message' => nil,
        'failure_command'        => nil,
        'failure_actions'        => nil,
        'failure_delay'          => 0,
        'service_name'           => nil,
        'host'                   => nil
      }

      # Validate the hash options
      options.each{ |key, value|
        key = key.to_s.downcase
        unless opts.include?(key)
          raise ArgumentError, "Invalid option '#{key}'"
        end
        opts[key] = value
      }
         
      unless opts['service_name']
        raise ArgumentError, 'No service_name specified'            
      end
         
      service = opts.delete('service_name')
      host = opts.delete('host')

      raise TypeError unless service.is_a?(String)
      raise TypeError unless host.is_a?(String) if host

      begin
        handle_scm = OpenSCManager(host, 0, SC_MANAGER_CONNECT)

        if handle_scm == 0
          raise Error, get_last_error
        end
         
        desired_access = SERVICE_CHANGE_CONFIG
         
        if opts['failure_actions']
          desired_access |= SERVICE_START
        end

        handle_scs = OpenService(
          handle_scm,
          service,
          desired_access
        )

        if handle_scs == 0
          raise Error, get_last_error
        end

        dependencies = opts['dependencies']

        if dependencies && !dependencies.empty?
          unless dependencies.is_a?(Array) || dependencies.is_a?(String)
            raise TypeError, 'dependencies must be a string or array'
          end

          if dependencies.is_a?(Array)
            dependencies = dependencies.join("\000")
          end
            
          dependencies += "\000"
        end

        bool = ChangeServiceConfig(
          handle_scs,
          opts['service_type'],
          opts['start_type'],
          opts['error_control'],
          opts['binary_path_name'],
          opts['load_order_group'],
          0,
          dependencies,
          opts['service_start_name'],
          opts['password'],
          opts['display_name']
        )

        unless bool
          raise Error, get_last_error
        end

        if opts['description']
          description = 0.chr * 4 # sizeof(SERVICE_DESCRIPTION)
          description[0,4] = [opts['description']].pack('p*')

          bool = ChangeServiceConfig2(
            handle_scs,
            SERVICE_CONFIG_DESCRIPTION,
            description
          )

          unless bool
            raise Error, get_last_error
          end
        end

        if opts['failure_reset_period'] || opts['failure_reboot_message'] ||
           opts['failure_command'] || opts['failure_actions']
        then
          configure_failure_actions(handle_scs, opts)
        end
      ensure
        CloseServiceHandle(handle_scs) if handle_scs && handle_scs > 0
        CloseServiceHandle(handle_scm) if handle_scm && handle_scm > 0
      end

      self
    end
      
    # Returns whether or not +service+ exists on +host+ or localhost, if
    # no host is specified.
    #
    # Example:
    #
    # Service.exists?('W32Time') => true
    # 
    def self.exists?(service, host=nil)
      bool = false

      begin
        handle_scm = OpenSCManager(host, 0, SC_MANAGER_ENUMERATE_SERVICE)
         
        if handle_scm == 0
          raise Error, get_last_error
        end
         
        handle_scs = OpenService(handle_scm, service, SERVICE_QUERY_STATUS)
        bool = true if handle_scs > 0
      ensure
        CloseServiceHandle(handle_scm) if handle_scm && handle_scm > 0
        CloseServiceHandle(handle_scs) if handle_scs && handle_scs > 0
      end

      bool         
    end
      
    # Returns the display name of the specified service name, i.e. the string
    # displayed in the Services GUI. Raises a Service::Error if the service
    # name cannot be found.
    #
    # If a +host+ is provided, the information will be retrieved from that
    # host. Otherwise, the information is pulled from the local host (the
    # default behavior).
    #
    # Example:
    #
    # Service.get_display_name('W32Time') => 'Windows Time'
    #
    def self.get_display_name(service, host=nil)
      handle_scm = OpenSCManager(host, 0, SC_MANAGER_CONNECT)
        
      if handle_scm == 0
        raise Error, get_last_error
      end
         
      display_name = 0.chr * 260
      display_buf  = [display_name.size].pack('L')

      begin
        bool = GetServiceDisplayName(
          handle_scm,
          service,
          display_name,
          display_buf
        )

        unless bool
          raise Error, get_last_error
        end
      ensure
        CloseServiceHandle(handle_scm)
      end

      display_name.unpack('Z*')[0]
    end
      
    # Returns the service name of the specified service from the provided
    # +display_name+. Raises a Service::Error if the +display_name+ cannote
    # be found.
    #
    # If a +host+ is provided, the information will be retrieved from that
    # host. Otherwise, the information is pulled from the local host (the
    # default behavior).
    #
    # Example:
    #
    # Service.get_service_name('Windows Time') => 'W32Time'
    #
    def self.get_service_name(display_name, host=nil)
      handle_scm = OpenSCManager(host, 0, SC_MANAGER_CONNECT)
       
      if handle_scm == 0
        raise Error, get_last_error
      end
         
      service_name = 0.chr * 260
      service_buf  = [service_name.size].pack('L')
         
      begin
        bool = GetServiceKeyName(
          handle_scm,
          display_name,
          service_name,
          service_buf
        )

        unless bool
          raise Error, get_last_error
        end
      ensure
        CloseServiceHandle(handle_scm)
      end

      service_name.unpack('Z*')[0]
    end

    # Attempts to start the named +service+ on +host+, or the local machine
    # if no host is provided. If +args+ are provided, they are passed to the
    # Daemon#service_main method.
    #
    # Examples:
    #
    #    # Start 'SomeSvc' on the local machine
    #    Service.start('SomeSvc', nil) => self
    #
    #    # Start 'SomeSvc' on host 'foo', passing 'hello' as an argument
    #    Service.start('SomeSvc', 'foo', 'hello') => self
    #     
    def self.start(service, host=nil, *args)
      handle_scm = OpenSCManager(host, nil, SC_MANAGER_CONNECT)
    
      if handle_scm == 0
	      raise Error, get_last_error
      end
         
      begin
        handle_scs = OpenService(handle_scm, service, SERVICE_START)
                  
        if handle_scs == 0
          raise Error, get_last_error
        end
           
        num_args = 0
         
        if args.empty?
          args = nil
        else
          num_args = args.length
          args = args.map{ |x| [x].pack('p*') }.join
        end     
           
        unless StartService(handle_scs, num_args, args)
          raise Error, get_last_error
        end
           
      ensure
        CloseServiceHandle(handle_scs) if handle_scs && handle_scs > 0
        CloseServiceHandle(handle_scm)
      end
        
      self                          
    end
      
    # Stops a the given +service+ on +host+, or the local host if no host
    # is specified. Returns self.
    #
    # Note that attempting to stop an already stopped service raises
    # Service::Error.
    #
    # Example:
    #
    #    Service.stop('W32Time') => self
    #      
    def self.stop(service, host=nil)
      service_signal = SERVICE_STOP
      control_signal = SERVICE_CONTROL_STOP
      send_signal(service, host, service_signal, control_signal)
      self
    end
      
    # Pauses the given +service+ on +host+, or the local host if no host
    # is specified. Returns self
    #
    # Note that pausing a service that is already paused will have
    # no effect and it will not raise an error.
    #
    # Be aware that not all services are configured to accept a pause
    # command. Attempting to pause a service that isn't setup to receive
    # a pause command will raise an error.
    #
    # Example:
    #
    #    Service.pause('Schedule') => self
    #      
    def self.pause(service, host=nil)
      service_signal = SERVICE_PAUSE_CONTINUE
      control_signal = SERVICE_CONTROL_PAUSE
      send_signal(service, host, service_signal, control_signal)
      self
    end
      
    # Resume the given +service+ on +host+, or the local host if no host
    # is specified. Returns self.
    #
    # Note that resuming a service that's already running will have no
    # effect and it will not raise an error.
    #
    # Example:
    #
    #    Service.resume('Schedule') => self
    #    
    def self.resume(service, host=nil)
      service_signal = SERVICE_PAUSE_CONTINUE
      control_signal = SERVICE_CONTROL_CONTINUE
      send_signal(service, host, service_signal, control_signal)
      self
    end
      
    # Deletes the specified +service+ from +host+, or the local host if
    # no host is specified. Returns self.
    #
    # Technical note. This method is not instantaneous. The service is first
    # marked for deletion from the service control manager database. Then all
    # handles to the service are closed. Then an attempt to stop the service
    # is made. If the service cannot be stopped, the service control manager
    # database entry is removed when the system is restarted.
    #
    # Example:
    #
    #   Service.delete('SomeService') => self
    #
    def self.delete(service, host=nil)
      handle_scm = OpenSCManager(host, 0, SC_MANAGER_CREATE_SERVICE)
       
      if handle_scm == 0
        raise Error, get_last_error
      end
       
      begin
        handle_scs = OpenService(handle_scm, service, DELETE)

        if handle_scs == 0
          raise Error, get_last_error
        end
       
        unless DeleteService(handle_scs)
          raise Error, get_last_error
        end
      ensure
        CloseServiceHandle(handle_scs) if handle_scs && handle_scs > 0
        CloseServiceHandle(handle_scm)
      end

      self
    end

    # Returns a ServiceConfigInfo struct containing the configuration
    # information about +service+ on +host+, or the local host if no
    # host is specified.
    #
    # Example:
    #
    #   Service.config_info('W32Time') => <struct ServiceConfigInfo ...>
    #--
    # This contains less information that the ServiceInfo struct that
    # is returned with the Service.services method, but is faster for
    # looking up basic information for a single service.
    #
    def self.config_info(service, host=nil)
      raise TypeError if host && !host.is_a?(String)

      handle_scm = OpenSCManager(host, nil, SC_MANAGER_ENUMERATE_SERVICE)

      if handle_scm == 0
        raise Error, get_last_error
      end

      begin
        handle_scs = OpenService(handle_scm, service, SERVICE_QUERY_CONFIG)

        if handle_scs == 0
          raise Error, get_last_error
        end

        # First, get the buf size needed
        bytes_needed = [0].pack('L')

        bool = QueryServiceConfig(handle_scs, nil, 0, bytes_needed)

        if !bool && GetLastError() != ERROR_INSUFFICIENT_BUFFER
          raise Error, get_last_error
        end

        buf = 0.chr * bytes_needed.unpack('L')[0]
        bytes = [0].pack('L')

        bool = QueryServiceConfig(handle_scs, buf, buf.size, bytes_needed)

        unless bool
          raise Error, get_last_error
        end
      ensure
        CloseServiceHandle(handle_scs) if handle_scs && handle_scs > 0
        CloseServiceHandle(handle_scm)
      end

      binary_path_name   = 0.chr * 1024
      load_order_group   = 0.chr * 1024
      dependencies       = 0.chr * 1024
      service_start_name = 0.chr * 260
      display_name       = 0.chr * 260

      strcpy(binary_path_name, buf[12,4].unpack('L')[0])
      binary_path_name = binary_path_name.unpack('Z*')[0]

      strcpy(load_order_group, buf[16,4].unpack('L')[0])
      load_order_group = load_order_group.unpack('Z*')[0]

      dependencies = get_dependencies(buf[24,4].unpack('L').first)

      strcpy(service_start_name, buf[28,4].unpack('L')[0])
      service_start_name = service_start_name.unpack('Z*')[0]

      strcpy(display_name, buf[32,4].unpack('L')[0])
      display_name = display_name.unpack('Z*')[0]

      ConfigStruct.new(
        get_service_type(buf[0,4].unpack('L')[0]),
        get_start_type(buf[4,4].unpack('L')[0]),
        get_error_control(buf[8,4].unpack('L')[0]),
        binary_path_name,
        load_order_group,
        buf[20,4].unpack('L')[0],
        dependencies,
        service_start_name,
        display_name
      )
    end
      
    # Returns a ServiceStatus struct indicating the status of service +name+
    # on +host+, or the localhost if none is provided.
    #
    # Example:
    #
    # Service.status('W32Time') => <struct Struct::ServiceStatus ...>
    #
    def self.status(service, host=nil)
      handle_scm = OpenSCManager(host, 0, SC_MANAGER_ENUMERATE_SERVICE)
          
      if handle_scm == 0
        raise Error, get_last_error
      end
           
      begin
        handle_scs = OpenService(
          handle_scm,
          service,
          SERVICE_QUERY_STATUS
        )
           
        if handle_scs == 0
          raise Error, get_last_error
        end
           
        # SERVICE_STATUS_PROCESS struct
        status = [0,0,0,0,0,0,0,0,0].pack('LLLLLLLLL')
        bytes  = [0].pack('L')
           
        bool = QueryServiceStatusEx(
          handle_scs,
          SC_STATUS_PROCESS_INFO,
          status,
          status.size,
          bytes
        )
           
        unless bool
          raise Error, get_last_error
        end
           
        dw_service_type = status[0,4].unpack('L').first
           
        service_type  = get_service_type(dw_service_type)
        current_state = get_current_state(status[4,4].unpack('L').first)
        controls      = get_controls_accepted(status[8,4].unpack('L').first)
        interactive   = dw_service_type & SERVICE_INTERACTIVE_PROCESS > 0
           
        # Note that the pid and service flags will always return 0 if you're
        # on Windows NT 4 or using a version of Ruby compiled with VC++ 6
        # or earlier.
        # 
        status_struct = StatusStruct.new(
          service_type,
          current_state,
          controls,
          status[12,4].unpack('L').first, # Win32ExitCode
          status[16,4].unpack('L').first, # ServiceSpecificExitCode
          status[20,4].unpack('L').first, # CheckPoint
          status[24,4].unpack('L').first, # WaitHint
          interactive,
          status[28,4].unpack('L').first, # ProcessId
          status[32,4].unpack('L').first  # ServiceFlags
        )
           
      ensure
        CloseServiceHandle(handle_scs) if handle_scs && handle_scs > 0
        CloseServiceHandle(handle_scm)
      end
       
      status_struct
    end

    # Enumerates over a list of service types on +host+, or the local
    # machine if no host is specified, yielding a ServiceInfo struct for
    # each service.
    #
    # If a +group+ is specified, then only those services that belong to
    # that load order group are enumerated. If an empty string is provided,
    # then only services that do not belong to any group are enumerated. If
    # this parameter is nil (the default), group membership is ignored and
    # all services are enumerated. This value is not case sensitive.
    #
    # Examples:
    #
    #    # Enumerate over all services on the localhost
    #    Service.services{ |service| p service }
    #
    #    # Enumerate over all services on a remote host
    #    Service.services('some_host'){ |service| p service }
    #
    #    # Enumerate over all 'network' services locally
    #    Service.services(nil, 'network'){ |service| p service }
    #  
    def self.services(host=nil, group=nil)
      unless host.nil?
        raise TypeError unless host.is_a?(String) # Avoid strange errors
      end
         
      unless group.nil?
        raise TypeError unless group.is_a?(String) # Avoid strange errors
      end
                       
      handle_scm = OpenSCManager(host, 0, SC_MANAGER_ENUMERATE_SERVICE)
         
      if handle_scm == 0
        raise Error, get_last_error
      end
          
      bytes_needed      = [0].pack('L')
      services_returned = [0].pack('L')
      resume_handle     = [0].pack('L')

      begin
        # The first call is used to determine the required buffer size
        bool = EnumServicesStatusEx(
          handle_scm,
          SC_ENUM_PROCESS_INFO,
          SERVICE_WIN32 | SERVICE_DRIVER,
          SERVICE_STATE_ALL,
          0,
          0,
          bytes_needed,
          services_returned,
          resume_handle,
          group
        )

        err_num = GetLastError()

        if !bool && err_num == ERROR_MORE_DATA
          service_buf = 0.chr * bytes_needed.unpack('L').first
        else
          raise Error, get_last_error(err_num)
        end
          
        bool = EnumServicesStatusEx(
          handle_scm,
          SC_ENUM_PROCESS_INFO,
          SERVICE_WIN32 | SERVICE_DRIVER,
          SERVICE_STATE_ALL,
          service_buf,
          service_buf.size,
          bytes_needed,
          services_returned,
          resume_handle,
          group
        )
         
        unless bool
          raise Error, get_last_error
        end

        num_services = services_returned.unpack('L').first
           
        index = 0
        services_array = [] unless block_given?

        1.upto(num_services){ |num|
          service_name = 0.chr * 260
          display_name = 0.chr * 260

          info = service_buf[index, 44] # sizeof(SERVICE_STATUS_PROCESS)

          strcpy(service_name, info[0,4].unpack('L').first)
          strcpy(display_name, info[4,4].unpack('L').first)

          service_name = service_name.unpack('Z*')[0]
          display_name = display_name.unpack('Z*')[0]
             
          dw_service_type = info[8,4].unpack('L').first
       
          service_type  = get_service_type(dw_service_type)
          current_state = get_current_state(info[12,4].unpack('L').first)
          controls      = get_controls_accepted(info[16,4].unpack('L').first)
          interactive   = dw_service_type & SERVICE_INTERACTIVE_PROCESS > 0
          win_exit_code = info[20,4].unpack('L').first
          ser_exit_code = info[24,4].unpack('L').first
          check_point   = info[28,4].unpack('L').first
          wait_hint     = info[32,4].unpack('L').first
          pid           = info[36,4].unpack('L').first
          service_flags = info[40,4].unpack('L').first

          begin
            handle_scs = OpenService(
              handle_scm,
              service_name,
              SERVICE_QUERY_CONFIG
            )
               
            if handle_scs == 0
              raise Error, get_last_error
            end

            config_buf = get_config_info(handle_scs)

            if config_buf != ERROR_FILE_NOT_FOUND
              binary_path = 0.chr * 1024
              strcpy(binary_path, config_buf[12,4].unpack('L').first)
              binary_path = binary_path.unpack('Z*')[0]

              load_order = 0.chr * 1024
              strcpy(load_order, config_buf[16,4].unpack('L').first)
              load_order = load_order.unpack('Z*')[0]
           
              start_name = 0.chr * 1024
              strcpy(start_name, config_buf[28,4].unpack('L').first)
              start_name = start_name.unpack('Z*')[0]
            
              start_type = get_start_type(config_buf[4,4].unpack('L').first)
              error_ctrl = get_error_control(config_buf[8,4].unpack('L').first)

              tag_id = config_buf[20,4].unpack('L').first

              deps = get_dependencies(config_buf[24,4].unpack('L').first)

              description = 0.chr * 2048
              buf = get_config2_info(handle_scs, SERVICE_CONFIG_DESCRIPTION) 

              strcpy(description, buf[0,4].unpack('L').first)
              description = description.unpack('Z*')[0]
            else
              msg = "WARNING: The registry entry for the #{service_name} "
              msg += "service could not be found."
              warn msg
             
              binary_path = nil
              load_order  = nil
              start_name  = nil
              start_type  = nil
              error_ctrl  = nil
              tag_id      = nil
              deps        = nil
              description = nil
            end
            
            buf2 = get_config2_info(handle_scs, SERVICE_CONFIG_FAILURE_ACTIONS)
            
            if buf2 != ERROR_FILE_NOT_FOUND
              reset_period = buf2[0,4].unpack('L').first
            
              reboot_msg = 0.chr * 260
              strcpy(reboot_msg, buf2[4,4].unpack('L').first)
              reboot_msg = reboot_msg.unpack('Z*')[0]
            
              command = 0.chr * 260
              strcpy(command, buf2[8,4].unpack('L').first)
              command = command.unpack('Z*')[0]
            
              num_actions = buf2[12,4].unpack('L').first
              actions = nil
            
              if num_actions > 0
                action_ptr = buf2[16,4].unpack('L').first
                action_buf = [0,0].pack('LL') * num_actions
                memcpy(action_buf, action_ptr, action_buf.size)
               
                i = 0
                actions = {}
                num_actions.times{ |n|
                  action_type, delay = action_buf[i, 8].unpack('LL')
                  action_type = get_action_type(action_type)
                  actions[n+1] = {:action_type => action_type, :delay => delay}
                  i += 8
                }
              end
            else
              reset_period   = nil
              reboot_message = nil
              command        = nil
              actions        = nil
            end
          ensure
            CloseServiceHandle(handle_scs) if handle_scs > 0
          end
          
          struct = ServiceStruct.new(
            service_name,
            display_name,
            service_type,
            current_state,
            controls,
            win_exit_code,
            ser_exit_code,
            check_point,
            wait_hint,
            binary_path,
            start_type,
            error_ctrl,
            load_order,
            tag_id,
            start_name,
            deps,
            description,
            interactive,
            pid,
            service_flags,
            reset_period,
            reboot_msg,
            command,
            num_actions,
            actions
          )
          
          if block_given?
             yield struct
          else
             services_array << struct
          end

          index += 44 # sizeof(SERVICE_STATUS_PROCESS)
        }
      ensure
        CloseServiceHandle(handle_scm)
      end
       
      block_given? ? nil : services_array
    end
      
    private
      
    # Configures failure actions for a given service.
    #
    def self.configure_failure_actions(handle_scs, opts)
      if opts['failure_actions']
        token_handle = 0.chr * 4
                        
        bool = OpenProcessToken(
          GetCurrentProcess(),
          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
          token_handle
        )
                           
        unless bool
          error = get_last_error
          CloseServiceHandle(handle_scs)
          raise Error, error            
        end
                           
        token_handle = token_handle.unpack('L').first
                     
        # Get the LUID for shutdown privilege.
        luid = 0.chr * 8
                     
        unless LookupPrivilegeValue('', 'SeShutdownPrivilege', luid)
          error = get_last_error
          CloseServiceHandle(handle_scs)
          raise Error, error                
        end
                     
        tkp = [1].pack('L') + luid + [SE_PRIVILEGE_ENABLED].pack('L')
                        
        # Enable shutdown privilege in access token of this process
        bool = AdjustTokenPrivileges(
          token_handle,
          0,
          tkp,
          tkp.size,
          nil,
          nil
        )
                        
        unless bool
          error = get_last_error
          CloseServiceHandle(handle_scs)
          raise Error, error                
        end                              
      end             
                              
      fail_buf = 0.chr * 20 # sizeof(SERVICE_FAILURE_ACTIONS)

      if opts['failure_reset_period']
        fail_buf[0,4] = [opts['failure_reset_period']].pack('L')
      end
         
      if opts['failure_reboot_message']
        fail_buf[4,4] = [opts['failure_reboot_message']].pack('p*')
      end
         
      if opts['failure_command']
        fail_buf[8,4] = [opts['failure_command']].pack('p*')
      end
         
      if opts['failure_actions']
        actions = []
        
        opts['failure_actions'].each{ |action|
          action_buf = 0.chr * 8
          action_buf[0, 4] = [action].pack('L')
          action_buf[4, 4] = [opts['failure_delay']].pack('L')
          actions << action_buf
        }
                        
        actions = actions.join
       
        fail_buf[12,4] = [opts['failure_actions'].length].pack('L')
        fail_buf[16,4] = [actions].pack('p*')
      end
         
      bool = ChangeServiceConfig2(
        handle_scs,
        SERVICE_CONFIG_FAILURE_ACTIONS,
        fail_buf
      )
         
      unless bool
        error = get_last_error
        CloseServiceHandle(handle_scs)
        raise Error, error
      end         
    end

    # Unravels a pointer to an array of dependencies. Takes the address
    # that points the array as an argument.
    #
    def self.get_dependencies(address)
      dep_buf = "" 

      while address != 0
        char_buf = 0.chr
        memcpy(char_buf, address, 1)
        address += 1             
        dep_buf += char_buf
        break if dep_buf[-2,2] == "\0\0"             
      end

      dependencies = []

      if dep_buf != "\0\0"
        dependencies = dep_buf.split("\000\000").first.split(0.chr)
      end

      dependencies
    end
      
    # Returns a human readable string indicating the action type.
    #
    def self.get_action_type(action_type)
      case action_type
        when SC_ACTION_NONE
          'none'
        when SC_ACTION_REBOOT
          'reboot'
        when SC_ACTION_RESTART
          'restart'
        when SC_ACTION_RUN_COMMAND
          'command'
        else
          'unknown'
       end
    end

    # Shortcut for QueryServiceConfig. Returns the buffer. In rare cases
    # the underlying registry entry may have been deleted, but the service
    # still exists. In that case, the ERROR_FILE_NOT_FOUND value is returned
    # instead.
    #
    def self.get_config_info(handle)
      bytes_needed = [0].pack('L')

      # First attempt at QueryServiceConfig is to get size needed
      bool = QueryServiceConfig(handle, 0, 0, bytes_needed)

      err_num = GetLastError()

      if !bool && err_num == ERROR_INSUFFICIENT_BUFFER
        config_buf = 0.chr * bytes_needed.unpack('L').first
      elsif err_num == ERROR_FILE_NOT_FOUND
        return err_num
      else
        error = get_last_error(err_num)
        CloseServiceHandle(handle)
        raise Error, error
      end

      bytes_needed = [0].pack('L')

      # Second attempt at QueryServiceConfig gets the actual info
      begin
        bool = QueryServiceConfig(
          handle,
          config_buf,
          config_buf.size,
          bytes_needed
        )

        raise Error, get_last_error unless bool
      ensure
        CloseServiceHandle(handle) unless bool
      end

      config_buf
    end
      
    # Shortcut for QueryServiceConfig2. Returns the buffer.
    # 
    def self.get_config2_info(handle, info_level)     
      bytes_needed = [0].pack('L')
         
      # First attempt at QueryServiceConfig2 is to get size needed
      bool = QueryServiceConfig2(handle, info_level, 0, 0, bytes_needed)

      err_num = GetLastError()

      if !bool && err_num == ERROR_INSUFFICIENT_BUFFER
        config2_buf = 0.chr * bytes_needed.unpack('L').first
      elsif err_num == ERROR_FILE_NOT_FOUND
        return err_num
      else
        CloseServiceHandle(handle)
        raise Error, get_last_error(err_num)
      end
         
      bytes_needed = [0].pack('L')

      # Second attempt at QueryServiceConfig2 gets the actual info
      begin
        bool = QueryServiceConfig2(
          handle,
          info_level,
          config2_buf,
          config2_buf.size,
          bytes_needed
        )

        raise Error, get_last_error unless bool
      ensure
        CloseServiceHandle(handle) unless bool
      end
       
      config2_buf
    end
      
    # Returns a human readable string indicating the error control
    #
    def self.get_error_control(error_control)
      case error_control
        when SERVICE_ERROR_CRITICAL
          'critical'
        when SERVICE_ERROR_IGNORE
          'ignore'
        when SERVICE_ERROR_NORMAL
          'normal'
        when SERVICE_ERROR_SEVERE
          'severe'
        else
          nil
      end
    end
      
    # Returns a human readable string indicating the start type.
    #
    def self.get_start_type(start_type)
      case start_type
        when SERVICE_AUTO_START
          'auto start'
        when SERVICE_BOOT_START
          'boot start'
        when SERVICE_DEMAND_START
          'demand start'
        when SERVICE_DISABLED
          'disabled'
        when SERVICE_SYSTEM_START
          'system start'
        else
          nil
      end
    end
      
    # Returns an array of human readable strings indicating the controls
    # that the service accepts.
    #
    def self.get_controls_accepted(controls)
      array = []

      if controls & SERVICE_ACCEPT_NETBINDCHANGE > 0
        array << 'netbind change'
      end

      if controls & SERVICE_ACCEPT_PARAMCHANGE > 0
        array << 'param change'
      end

      if controls & SERVICE_ACCEPT_PAUSE_CONTINUE > 0
        array << 'pause continue'
      end

      if controls & SERVICE_ACCEPT_SHUTDOWN > 0
        array << 'shutdown'
      end

      if controls & SERVICE_ACCEPT_PRESHUTDOWN > 0
        array << 'pre-shutdown'
      end

      if controls & SERVICE_ACCEPT_STOP > 0
        array << 'stop'
      end

      if controls & SERVICE_ACCEPT_HARDWAREPROFILECHANGE > 0
        array << 'hardware profile change'
      end

      if controls & SERVICE_ACCEPT_POWEREVENT > 0
        array << 'power event'
      end

      if controls & SERVICE_ACCEPT_SESSIONCHANGE > 0
        array << 'session change'
      end

      array
    end
      
    # Converts a service state numeric constant into a readable string.
    # 
    def self.get_current_state(state)
      case state
        when SERVICE_CONTINUE_PENDING
          'continue pending'
        when SERVICE_PAUSE_PENDING
          'pause pending'
        when SERVICE_PAUSED
          'paused'
        when SERVICE_RUNNING
          'running'
        when SERVICE_START_PENDING
          'start pending'
        when SERVICE_STOP_PENDING
          'stop pending'
        when SERVICE_STOPPED
          'stopped'
        else
          nil
      end
    end
      
    # Converts a service type numeric constant into a human readable string.
    # 
    def self.get_service_type(service_type)
      case service_type
        when SERVICE_FILE_SYSTEM_DRIVER
          'file system driver'
        when SERVICE_KERNEL_DRIVER
          'kernel driver'
        when SERVICE_WIN32_OWN_PROCESS
          'own process'
        when SERVICE_WIN32_SHARE_PROCESS
          'share process'
        when SERVICE_RECOGNIZER_DRIVER
          'recognizer driver'
        when SERVICE_DRIVER
          'driver'
        when SERVICE_WIN32
          'win32'
        when SERVICE_TYPE_ALL
          'all'
        when SERVICE_INTERACTIVE_PROCESS | SERVICE_WIN32_OWN_PROCESS
          'own process, interactive'
        when SERVICE_INTERACTIVE_PROCESS | SERVICE_WIN32_SHARE_PROCESS
          'share process, interactive'
        else
          nil
      end
    end
      
    # A shortcut method that simplifies the various service control methods.
    # 
    def self.send_signal(service, host, service_signal, control_signal)
      handle_scm = OpenSCManager(host, 0, SC_MANAGER_CONNECT)
         
      if handle_scm == 0
        raise Error, get_last_error
      end
         
      begin
        handle_scs = OpenService(handle_scm, service, service_signal)
         
        if handle_scs == 0
          raise Error, get_last_error
        end
         
        status = [0,0,0,0,0,0,0].pack('LLLLLLL')
         
        unless ControlService(handle_scs, control_signal, status)
          raise Error, get_last_error
        end        
      ensure
        CloseServiceHandle(handle_scs) if handle_scs && handle_scs > 0
        CloseServiceHandle(handle_scm) if handle_scm && handle_scm > 0
      end
         
      status
    end

    class << self
      alias create new
      alias getdisplayname get_display_name
      alias getservicename get_service_name
    end
  end
end
