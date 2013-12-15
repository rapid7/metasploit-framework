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
    access = opts[:access] || 0xF003F
    machine_str = host ? "\\\\#{host}" : nil

    # SC_HANDLE WINAPI OpenSCManager(
    #   _In_opt_  LPCTSTR lpMachineName,
    #   _In_opt_  LPCTSTR lpDatabaseName,
    #   _In_      DWORD dwDesiredAccess
    # );
    manag = session.railgun.advapi32.OpenSCManagerA(machine_str,nil,access)
    if (manag["return"] == 0)
      raise RuntimeError.new("Unable to open service manager, GetLastError: #{manag["GetLastError"]}")
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
  # @return [Array] The names of the services.
  #
  # @todo Rewrite to allow operating on a remote host
  #
  def service_list
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
            services << sk
          end
        rescue
        end
      }
      a.push(t)
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
  # @param name [String] The target service's name (not to be confused
  #   with Display Name). Case sensitive.
  #
  # @return [Hash]
  #
  # @todo Rewrite to allow operating on a remote host
  #
  def service_info(name)
    service = {}
    servicekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{name.chomp}"
    service["Name"] = registry_getvaldata(servicekey,"DisplayName").to_s
    srvstart = registry_getvaldata(servicekey,"Start").to_i
    if srvstart == 2
      service["Startup"] = "Auto"
    elsif srvstart == 3
      service["Startup"] = "Manual"
    elsif srvstart == 4
      service["Startup"] = "Disabled"
    end
    service["Command"] = registry_getvaldata(servicekey,"ImagePath").to_s
    service["Credentials"] = registry_getvaldata(servicekey,"ObjectName").to_s
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
  def service_change_startup(name,mode)
    servicekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{name.chomp}"
    case mode.downcase
    when "auto" then
      registry_setvaldata(servicekey,"Start","2","REG_DWORD")
    when "manual" then
      registry_setvaldata(servicekey,"Start","3","REG_DWORD")
    when "disable" then
      registry_setvaldata(servicekey,"Start","4","REG_DWORD")
    end
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

    # SC_MANAGER_CONNECT           0x01
    # SC_MANAGER_CREATE_SERVICE    0x02
    # SC_MANAGER_QUERY_LOCK_STATUS 0x10
    open_sc_manager(:host=>server, :access=>0x13) do |manager|
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
      newservice = adv.CreateServiceA(manager, name, display_name,
        0x0010, 0X00000010, startup, 0, executable_on_host,
        nil, nil, nil, nil, nil)
      adv.CloseServiceHandle(newservice["return"])
      if newservice["GetLastError"] == 0
        return true
      else
        return false
      end
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
      # open with access SERVICE_START (0x0010)
      handle = adv.OpenServiceA(manager, name, 0x10)
      if(handle["return"] == 0)
        raise RuntimeError.new("Could not open service. OpenServiceA error: #{handle["GetLastError"]}")
      end
      retval = adv.StartServiceA(handle["return"],0,nil)
      adv.CloseServiceHandle(handle["return"])

      # This is terrible. Magic return values should be refactored to
      # something meaningful.
      case retval["GetLastError"]
      when 0;    return 0 # everything worked
      when 1056; return 1 # service already started
      when 1058; return 2 # service disabled
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

    # SC_MANAGER_SERVICE_STOP (0x0020)
    open_sc_manager(:host=>server, :access=>1) do |manager|
      # open with SERVICE_STOP (0x0020)
      handle = adv.OpenServiceA(manager, name, 0x20)
      if(handle["return"] == 0)
        raise RuntimeError.new("Could not open service. OpenServiceA error: #{handle["GetLastError"]}")
      end
      retval = adv.ControlService(handle["return"],1,56)
      adv.CloseServiceHandle(handle["return"])

      case retval["GetLastError"]
      when 0;    return 0 # worked
      when 1062; return 1 # already stopped or disabled
      when 1052; return 2 # cannot be stopped
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
      # Thank you, Wine project for defining the DELETE constant since it,
      # and all its friends, are missing from the MSDN docs.
      # #define DELETE 0x00010000
      handle = adv.OpenServiceA(manager, name, 0x10000)
      if (handle["return"] == 0)
        raise RuntimeError.new("Could not open service. OpenServiceA error: #{handle["GetLastError"]}")
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
    
    # 0x80000000 GENERIC_READ 
    open_sc_manager(:host => server, :access => 0x80000000) do |manager|
      # Now to grab a handle to the service.
      handle = adv.OpenServiceA(manager, name, 0x80000000)
      if (handle["return"] == 0)
        raise RuntimeError.new("Could not open service. OpenServiceA error: #{handle["GetLastError"]}")
      end

      status = adv.QueryServiceStatus(handle["return"],28)
      if (status["return"] == 0)
        raise RuntimeError.new("Could not query service. QueryServiceStatus error: #{handle["GetLastError"]}")
      end

      vals = status['lpServiceStatus'].unpack('L*')
      adv.CloseServiceHandle(handle["return"])

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
  
    return ret
  end
end

end
end
end
