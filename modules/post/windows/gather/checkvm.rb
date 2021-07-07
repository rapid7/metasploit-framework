##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Process
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Virtual Environment Detection',
        'Description' => %q{
          This module attempts to determine whether the system is running
          inside of a virtual environment and if so, which one. This
          module supports detection of Hyper-V, VMWare, Virtual PC,
          VirtualBox, Xen, and QEMU.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Carlos Perez <carlos_perez[at]darkoperator.com>',
          'Aaron Soto <aaron_soto[at]rapid7.com>'
        ],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter', 'shell' ]
      )
    )
  end

  def get_services
    @services ||= registry_enumkeys('HKLM\SYSTEM\ControlSet001\Services')
    @services
  end

  def service_exists?(service)
    get_services && get_services.include?(service)
  end

  def hyperv?
    physical_host = registry_getvaldata('HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters', 'PhysicalHostNameFullyQualified')
    if physical_host
      report_note(
        host: session,
        type: 'host.physicalHost',
        data: { physicalHost: physical_host },
        update: :unique_data
      )
      print_good("This is a Hyper-V Virtual Machine running on physical host #{physical_host}")
      return true
    end

    sfmsvals = registry_enumkeys('HKLM\SOFTWARE\Microsoft')
    if sfmsvals
      return true if sfmsvals.include?('Hyper-V')
      return true if sfmsvals.include?('VirtualMachine')
    end

    return true if registry_getvaldata('HKLM\HARDWARE\DESCRIPTION\System', 'SystemBiosVersion') =~ /vrtual/i

    srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\FADT')
    return true if srvvals && srvvals.include?('VRTUAL')

    srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\RSDT')
    return true if srvvals && srvvals.include?('VRTUAL')

    return true if service_exists?('vmicexchange')

    key_path = 'HKLM\HARDWARE\DESCRIPTION\System'
    system_bios_version = registry_getvaldata(key_path, 'SystemBiosVersion')
    return true if system_bios_version && system_bios_version.include?('Hyper-V')

    key_path = 'HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0'
    return true if registry_getvaldata(key_path, 'Identifier') =~ /Msft    Virtual Disk    1.0/i

    false
  end

  def vmware?
    %w[vmdebug vmmouse VMTools VMMEMCTL].each do |service|
      return true if service_exists?(service)
    end

    return true if registry_getvaldata('HKLM\HARDWARE\DESCRIPTION\System\BIOS', 'SystemManufacturer') =~ /vmware/i
    return true if registry_getvaldata('HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0', 'Identifier') =~ /vmware/i

    vmwareprocs = [
      'vmwareuser.exe',
      'vmwaretray.exe'
    ]
    get_processes.each do |x|
      vmwareprocs.each do |p|
        return true if p == x['name'].downcase
      end
    end

    false
  end

  def virtualpc?
    %w[vpc-s3 vpcuhub msvmmouf].each do |service|
      return true if service_exists?(service)
    end

    vpcprocs = [
      'vmusrvc.exe',
      'vmsrvc.exe'
    ]
    get_processes.each do |x|
      vpcprocs.each do |p|
        return true if p == x['name'].downcase
      end
    end

    false
  end

  def virtualbox?
    vboxprocs = [
      'vboxservice.exe',
      'vboxtray.exe'
    ]
    get_processes.each do |x|
      vboxprocs.each do |p|
        return true if p == x['name'].downcase
      end
    end

    srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\DSDT')
    return true if srvvals && srvvals.include?('VBOX__')

    srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\FADT')
    return true if srvvals && srvvals.include?('VBOX__')

    srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\RSDT')
    return true if srvvals && srvvals.include?('VBOX__')

    key_path = 'HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0'
    return true if registry_getvaldata(key_path, 'Identifier') =~ /vbox/i

    return true if registry_getvaldata('HKLM\HARDWARE\DESCRIPTION\System', 'SystemBiosVersion') =~ /vbox/i

    %w[VBoxMouse VBoxGuest VBoxService VBoxSF].each do |service|
      return true if service_exists?(service)
    end

    false
  end

  def xen?
    xenprocs = [
      'xenservice.exe'
    ]
    get_processes.each do |x|
      xenprocs.each do |p|
        return true if p == x['name'].downcase
      end
    end

    srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\DSDT')
    return true if srvvals && srvvals.include?('Xen')

    srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\FADT')
    return true if srvvals && srvvals.include?('Xen')

    srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\RSDT')
    return true if srvvals && srvvals.include?('Xen')

    %w[xenevtchn xennet xennet6 xensvc xenvdb].each do |service|
      return true if service_exists?(service)
    end

    false
  end

  def qemu?
    key_path = 'HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0'
    return true if registry_getvaldata(key_path, 'Identifier') =~ /qemu/i

    key_path = 'HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0'
    return true if registry_getvaldata(key_path, 'ProcessorNameString') =~ /qemu/i

    false
  end

  def report_vm(hypervisor)
    print_good("This is a #{hypervisor} Virtual Machine")
    report_note(
      host: session,
      type: 'host.hypervisor',
      data: { hypervisor: hypervisor },
      update: :unique_data
    )
    report_virtualization(hypervisor)
  end

  def run
    print_status('Checking if the target is a Virtual Machine ...')

    if hyperv?
      report_vm('Hyper-V')
    elsif vmware?
      report_vm('VMware')
    elsif virtualpc?
      report_vm('VirtualPC')
    elsif virtualbox?
      report_vm('VirtualBox')
    elsif xen?
      report_vm('Xen')
    elsif qemu?
      report_vm('Qemu')
    else
      print_status('The target appears to be a Physical Machine')
    end
  end
end
