# -*- coding: binary -*-
require 'msf/core/post/windows/registry'

module Msf
class Post
module Windows


# @deprecated Use {Services} instead
module WindowsServices
  def self.included(base)
    include Services
  end

  def setup
    print_error("The Windows::WindowsServices mixin is deprecated, use Windows::Services instead")
    super
  end
end

#
# Post module mixin for dealing with Windows services
#
module Services

  START_TYPE = ["Boot","System","Auto","Manual","Disabled"]
  START_TYPE_BOOT       = 0
  START_TYPE_SYSTEM     = 1
  START_TYPE_AUTO       = 2
  START_TYPE MANUAL     = 3
  START_TYPE_DISABLED   = 4

  SERVICE_STOPPED           = 1
  SERVICE_START_PENDING     = 2
  SERVICE_STOP_PENDING      = 3
  SERVICE_RUNNING           = 4
  SERVICE_CONTINUE_PENDING  = 5
  SERVICE_PAUSE_PENDING     = 6
  SERVICE_PAUSED            = 7

  SC_MANAGER_CONNECT            = 0x0001
  SC_MANAGER_CREATE_SERVICE     = 0x0002
  SC_MANAGER_ENUMERATE_SERVICE  = 0x0004
  SC_MANAGER_LOCK               = 0x0008
  SC_MANAGER_QUERY_LOCK_STATUS  = 0x0010
  SC_MANAGER_MODIFY_BOOT_CONFIG = 0x0020
  SC_MANAGER_ALL_ACCESS         = 0xF003F

  SERVICE_QUERY_CONFIG          = 0x0001
  SERVICE_CHANGE_CONFIG         = 0x0002
  SERVICE_QUERY_STATUS          = 0x0004
  SERVICE_ENUMERATE_DEPENDENTS  = 0x0008
  SERVICE_START                 = 0x0010
  SERVICE_STOP                  = 0x0020
  SERVICE_PAUSE_CONTINUE        = 0x0040
  SERVICE_INTERROGATE           = 0x0080
  SERVICE_USER_DEFINED_CONTROL  = 0x0100
  SERVICE_ALL_ACCESS            = 0xF01FF

  SERVICE_NO_CHANGE             = 0xFFFFFFFF

  # Standard Access Rights
  DELETE                   = 0x00010000
  READ_CONTROL             = 0x00020000
  WRITE_DAC                = 0x00040000
  WRITE_OWNER              = 0x00080000
  ACCESS_SYSTEM_SECURITY   = 0x01000000

  # Generic Access Rights
  GENERIC_ALL              = 0x10000000
  GENERIC_EXECUTE          = 0x20000000
  GENERIC_WRITE            = 0x40000000
  GENERIC_READ             = 0x80000000

  SERVICE_KERNEL_DRIVER       = 0x01
  SERVICE_FILE_SYSTEM_DRIVER  = 0x02
  SERVICE_ADAPTER             = 0x04
  SERVICE_RECOGNIZER_DRIVER   = 0x08
  SERVICE_WIN32_OWN_PROCESS   = 0x10
  SERVICE_WIN32_SHARE_PROCESS = 0x20

  ERROR_SUCCESS                           = 0
  ERROR_ACCESS_DENIED                     = 0x5
  ERROR_INVALID_SERVICE_CONTROL           = 0x41C
  ERROR_SERVICE_REQUEST_TIMEOUT           = 0x41D
  ERROR_SERVICE_NO_THREAD                 = 0x41E
  ERROR_SERVICE_DATABASE_LOCKED           = 0x41F
  ERROR_SERVICE_ALREADY_RUNNING           = 0x420
  ERROR_INVALID_SERVICE_ACCOUNT           = 0x421
  ERROR_SERVICE_DISABLED                  = 0x422
  ERROR_CIRCULAR_DEPENDENCY               = 0x423
  ERROR_SERVICE_DOES_NOT_EXIST            = 0x424
  ERROR_SERVICE_CANNOT_ACCEPT_CTRL        = 0x425
  ERROR_SERVICE_NOT_ACTIVE                = 0x426
  ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 0x427
  ERROR_EXCEPTION_IN_SERVICE              = 0x428
  ERROR_DATABASE_DOES_NOT_EXIST           = 0x429
  ERROR_SERVICE_SPECIFIC_ERROR            = 0x42A
  ERROR_PROCESS_ABORTED                   = 0x42B
  ERROR_SERVICE_DEPENDENCY_FAIL           = 0x42C
  ERROR_SERVICE_LOGON_FAILED              = 0x42D
  ERROR_SERVICE_START_HANG                = 0x42E
  ERROR_INVALID_SERVICE_LOCK              = 0x42F
  ERROR_SERVICE_MARKED_FOR_DELETE         = 0x430
  ERROR_SERVICE_EXISTS                    = 0x431
  ERROR_ALREADY_RUNNING_LKG               = 0x432
  ERROR_SERVICE_DEPENDENCY_DELETED        = 0x433
  ERROR_BOOT_ALREADY_ACCEPTED             = 0x434
  ERROR_SERVICE_NEVER_STARTED             = 0x435
  ERROR_DUPLICATE_SERVICE_NAME            = 0x436
  ERROR_DIFFERENT_SERVICE_ACCOUNT         = 0x437
  ERROR_CANNOT_DETECT_DRIVER_FAILURE      = 0x438
  ERROR_CANNOT_DETECT_PROCESS_ABORT       = 0x439
  ERROR_NO_RECOVERY_PROGRAM               = 0x43A
  ERROR_SERVICE_NOT_IN_EXE                = 0x43B

  include ::Msf::Post::Windows::ExtAPI
  include ::Msf::Post::Windows::Registry

  #
  # Open the service manager with advapi32.dll!OpenSCManagerA on the
  # given host or the local machine if :host option is nil. If called
  # with a block, yields the manager and closes it when the block
  # returns.
  #
  # @param opts [Hash]
  # @option opts [String] :host (nil) The host on which to open the
  #   service manager. May be a hostname or IP address.
  # @option opts [Fixnum] :access (0xF003F) Bitwise-or of the
  #   SC_MANAGER_* constants (see
  #   {http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx})
  #
  # @return [Fixnum] Opaque Windows handle SC_HANDLE as returned by
  #   OpenSCManagerA()
  # @yield [manager] Gives the block a manager handle as returned by
  #   advapi32.dll!OpenSCManagerA. When the block returns, the handle
  #   will be closed with {#close_sc_manager}.
  # @raise [RuntimeError] if OpenSCManagerA returns a NULL handle
  #
  def open_sc_manager(opts={})
    host = opts[:host] || nil
    access = opts[:access] || SC_MANAGER_ALL_ACCESS
    machine_str = host ? "\\\\#{host}" : nil

    # SC_HANDLE WINAPI OpenSCManager(
    #   _In_opt_  LPCTSTR lpMachineName,
    #   _In_opt_  LPCTSTR lpDatabaseName,
    #   _In_      DWORD dwDesiredAccess
    # );
    manag = session.railgun.advapi32.OpenSCManagerA(machine_str,nil,access)
    if (manag["return"] == 0)
      raise RuntimeError.new("Unable to open service manager: #{manag["ErrorMessage"]}")
    end

    if (block_given?)
      begin
        yield manag["return"]
      ensure
        close_sc_manager(manag["return"])
      end
    else
      return manag["return"]
    end
  end

  #
  # Call advapi32.dll!CloseServiceHandle on the given handle
  #
  def close_sc_manager(handle)
    if handle
      session.railgun.advapi32.CloseServiceHandle(handle)
    end
  end

  #
  # List all Windows Services present
  #
  # @return [Array<Hash>] Array of Hashes containing Service details. May contain the following keys:
  #   * :name
  #   * :display
  #   * :pid
  #   * :status
  #   * :interactive
  #
  # @todo Rewrite to allow operating on a remote host
  #
  def service_list
    if load_extapi
      return session.extapi.service.enumerate
    else
      serviceskey = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
      a =[]
      services = []
      keys = registry_enumkeys(serviceskey)
      keys.each do |s|
        if a.length >= 10
          a.first.join
          a.delete_if {|x| not x.alive?}
        end
        t = framework.threads.spawn(self.refname+"-ServiceRegistryList",false,s) { |sk|
          begin
            srvtype = registry_getvaldata("#{serviceskey}\\#{sk}","Type").to_s
            if srvtype == "32" or srvtype == "16"
              services << {:name => sk }
            end
          rescue
          end
        }
        a.push(t)
      end
    end

    return services
  end

  #
  # Get Windows Service information.
  #
  # Information returned in a hash with display name, startup mode and
  # command executed by the service. Service name is case sensitive.  Hash
  # keys are Name, Start, Command and Credentials.
  #
  # If ExtAPI is available we return the DACL, LOGroup, and Interactive
  # values otherwise these values are nil
  #
  # @param name [String] The target service's name (not to be confused
  #   with Display Name). Case sensitive.
  #
  # @return [Hash]
  #
  # @todo Rewrite to allow operating on a remote host
  #
  def service_info(name)
    service = {}

    if load_extapi
      begin
        return session.extapi.service.query(name)
      rescue Rex::Post::Meterpreter::RequestError => e
          vprint_error("Request Error #{e}, falling back to registry technique")
      end
    end

    servicekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{name.chomp}"
    service[:display] = registry_getvaldata(servicekey,"DisplayName").to_s
    service[:starttype] = registry_getvaldata(servicekey,"Start").to_i
    service[:path] = registry_getvaldata(servicekey,"ImagePath").to_s
    service[:startname] = registry_getvaldata(servicekey,"ObjectName").to_s
    service[:dacl] = nil
    service[:logroup] = nil
    service[:interactive] = nil

    return service
  end

  #
  # Changes a given service startup mode, name must be provided and the mode.
  #
  # Mode is a string with either auto, manual or disable for the
  # corresponding setting. The name of the service is case sensitive.
  #
  # @todo Rewrite to allow operating on a remote host
  #
  def service_change_startup(name, mode)
    servicekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{name.chomp}"

    if mode.is_a? Integer
      startup_number = mode.to_s
    else
      # These are deliberately integers in strings
      case mode.downcase
        when "boot" then startup_number     = START_TYPE_BOOT.to_s
        when "system" then startup_number   = START_TYPE_SYSTEM.to_s
        when "auto" then startup_number     = START_TYPE_AUTO.to_s
        when "manual" then startup_number   = START_TYPE_MANUAL.to_s
        when "disable" then startup_number  = START_TYPE_DISABLED.to_s
        else
          raise RuntimeError, "Invalid Startup Mode: #{mode}"
      end
    end

    registry_setvaldata(servicekey,"Start",startup_number,"REG_DWORD")
  end

  #
  # Modify a service on the session host
  #
  # @param name [String] Name of the service to be used as the key
  # @param opts [Hash] Settings to be modified
  # @param server [String,nil] A hostname or IP address. Default is the
  #   remote localhost
  #
  # @return [true,false] True if there were no errors, false otherwise
  #
  def service_change_config(name, opts, server=nil)
    adv = session.railgun.advapi32

    open_sc_manager(:host=>server, :access=>SC_MANAGER_ALL_ACCESS) do |manager|

      service_handle = adv.OpenServiceA(manager,
                                     name,
                                     SERVICE_CHANGE_CONFIG)['return']
      if service_handle
        ret = adv.ChangeServiceConfigA(service_handle,
                                 opts[:service_type] || SERVICE_NO_CHANGE,
                                 opts[:start_type] || SERVICE_NO_CHANGE,
                                 opts[:error_control] || SERVICE_NO_CHANGE,
                                 opts[:bin_path_name] || nil,
                                 opts[:load_order_group] || nil,
                                 opts[:tag_id] || nil,
                                 opts[:dependencies] || nil,
                                 opts[:service_start_name] || nil,
                                 opts[:password] || nil,
                                 opts[:display_name] || nil)
        adv.CloseServiceHandle(service_handle)
        return (ret['return'] != 0)
      else
         return false
      end
    end

    return false
  end

  #
  # Create a service that runs +executable_on_host+ on the session host
  #
  # @param name [String] Name of the service to be used as the key
  # @param display_name [String] Name of the service as displayed by mmc
  # @param executable_on_host [String] EXE on the remote filesystem to
  #   be used as the service executable
  # @param startup [Fixnum] Constant used by CreateServiceA for startup
  #   type: 2 for Auto, 3 for Manual, 4 for Disable. Default is Auto
  # @param server [String,nil] A hostname or IP address. Default is the
  #   remote localhost
  #
  # @return [true,false] True if there were no errors, false otherwise
  #
  def service_create(name, display_name, executable_on_host, startup=2, server=nil)
    adv = session.railgun.advapi32

    access = SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_QUERY_LOCK_STATUS
    open_sc_manager(:host=>server, :access=>access) do |manager|
      # SC_HANDLE WINAPI CreateService(
      #  __in       SC_HANDLE hSCManager,
      #  __in       LPCTSTR lpServiceName,
      #  __in_opt   LPCTSTR lpDisplayName,
      #  __in       DWORD dwDesiredAccess,
      #  __in       DWORD dwServiceType,
      #  __in       DWORD dwStartType,
      #  __in       DWORD dwErrorControl,
      #  __in_opt   LPCTSTR lpBinaryPathName,
      #  __in_opt   LPCTSTR lpLoadOrderGroup,
      #  __out_opt  LPDWORD lpdwTagId,
      #  __in_opt   LPCTSTR lpDependencies,
      #  __in_opt   LPCTSTR lpServiceStartName,
      #  __in_opt   LPCTSTR lpPassword
      #);
      newservice = adv.CreateServiceA(manager,
                                      name,
                                      display_name,
                                      SERVICE_START,
                                      SERVICE_WIN32_OWN_PROCESS,
                                      startup,
                                      0,
                                      executable_on_host,
                                      nil, nil, nil, nil, nil)
      adv.CloseServiceHandle(newservice["return"])
      return (newservice["GetLastError"] == ERROR_SUCCESS)
    end
  end

  #
  # Start a service.
  #
  # @param name [String] Service name (not display name)
  # @param server [String,nil] A hostname or IP address. Default is the
  #   remote localhost
  #
  # @return [Fixnum] 0 if service started successfully, 1 if it failed
  #   because the service is already running, 2 if it is disabled
  #
  # @raise [RuntimeError] if OpenServiceA failed
  #
  def service_start(name, server=nil)
    adv = session.railgun.advapi32
    open_sc_manager(:host=>server, :access=>1) do |manager|
      # SC_HANDLE WINAPI OpenService(
      #   _In_  SC_HANDLE hSCManager,
      #   _In_  LPCTSTR lpServiceName,
      #   _In_  DWORD dwDesiredAccess
      # );

      handle = adv.OpenServiceA(manager, name, SERVICE_START)
      if(handle["return"] == 0)
        raise RuntimeError.new("Could not open service. OpenServiceA error: #{handle["ErrorMessage"]}")
      end
      retval = adv.StartServiceA(handle["return"],0,nil)
      adv.CloseServiceHandle(handle["return"])

      # This is terrible. Magic return values should be refactored to
      # something meaningful.
      case retval["GetLastError"]
      when ERROR_SUCCESS;    return 0 # everything worked
      when ERROR_SERVICE_ALREADY_RUNNING; return 1 # service already started
      when ERROR_SERVICE_DISABLED; return 2 # service disabled
      end
    end
  end

  #
  # Stop a service.
  #
  # @param (see #service_start)
  # @return [Fixnum] 0 if service stopped successfully, 1 if it failed
  #   because the service is already stopped or disabled, 2 if it
  #   cannot be stopped for some other reason.
  #
  # @raise (see #service_start)
  #
  def service_stop(name, server=nil)
    adv = session.railgun.advapi32

    open_sc_manager(:host=>server, :access=>SC_MANAGER_CONNECT) do |manager|
      handle = adv.OpenServiceA(manager, name, SERVICE_STOP)
      if(handle["return"] == 0)
        raise RuntimeError.new("Could not open service. OpenServiceA error: #{handle["ErrorMessage"]}")
      end
      retval = adv.ControlService(handle["return"],1,28)
      adv.CloseServiceHandle(handle["return"])

      case retval["GetLastError"]
        when ERROR_SUCCESS, ERROR_INVALID_SERVICE_CONTROL, ERROR_SERVICE_CANNOT_ACCEPT_CTRL, ERROR_SERVICE_NOT_ACTIVE
          status = parse_service_status_struct(status['lpServiceStatus'])
        else
          status = nil
      end

      case retval["GetLastError"]
      when ERROR_SUCCESS;    return 0 # worked
      when ERROR_SERVICE_NOT_ACTIVE; return 1 # already stopped or disabled
      when ERROR_INVALID_SERVICE_CONTROL, ERROR_DEPENDENT_SERVICES_RUNNING; return 2 # cannot be stopped
      end
    end
  end

  #
  # Delete a service.
  #
  # @param (see #service_start)
  #
  def service_delete(name, server=nil)
    adv = session.railgun.advapi32

    open_sc_manager(:host=>server) do |manager|
      # Now to grab a handle to the service.
      handle = adv.OpenServiceA(manager, name, DELETE)
      if (handle["return"] == 0)
        raise RuntimeError.new("Could not open service. OpenServiceA error: #{handle["ErrorMessage"]}")
      end

      # Lastly, delete it
      adv.DeleteService(handle["return"])

      adv.CloseServiceHandle(handle["return"])

      handle["GetLastError"]
    end
  end

  #
  # Query Service Status
  #
  # @param (see #service_start)
  #
  # @return {} representing lpServiceStatus
  #
  # @raise (see #service_start)
  #
  #
  def service_status(name, server=nil)
    adv = session.railgun.advapi32
    ret = nil

    open_sc_manager(:host => server, :access => GENERIC_READ) do |manager|
      # Now to grab a handle to the service.
      handle = adv.OpenServiceA(manager, name, GENERIC_READ)

      if (handle["return"] == 0)
        raise RuntimeError.new("Could not open service. OpenServiceA error: #{handle["ErrorMessage"]}")
      end

      status = adv.QueryServiceStatus(handle["return"],28)
      if (status["return"] == 0)
        raise RuntimeError.new("Could not query service. QueryServiceStatus error: #{handle["ErrorMessage"]}")
      end

      adv.CloseServiceHandle(handle["return"])

      parse_service_status_struct(status['lpServiceStatus'])
    end
  
    return ret
  end

  def parse_service_status_struct(lpServiceStatus)
    vals = lpServiceStatus.unpack('L*')
    ret = {
        :type              => vals[0],
        :state             => vals[1],
        :controls_accepted => vals[2],
        :win32_exit_code   => vals[3],
        :service_exit_code => vals[4],
        :check_point       => vals[5],
        :wait_hint         => vals[6]
    }
  end
end

end
end
end
