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
          VirtualBox, Xen, QEMU, Parallels and JoeSandbox.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Carlos Perez <carlos_perez[at]darkoperator.com>',
          'Aaron Soto <aaron_soto[at]rapid7.com>'
        ],
        'Platform' => [ 'win' ],
        'SessionTypes' => %w[meterpreter powershell shell],
        'References' => [
          ['URL', 'https://handlers.sans.org/tliston/ThwartingVMDetection_Liston_Skoudis.pdf'],
          ['URL', 'https://www.heise.de/security/downloads/07/1/1/8/3/5/5/9/vmde.pdf'],
          ['URL', 'https://evasions.checkpoint.com/techniques/registry.html']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
  end

  def get_services
    @services ||= registry_enumkeys('HKLM\\SYSTEM\\ControlSet001\\Services')
    @services
  end

  def service_exists?(service)
    get_services && get_services.include?(service)
  end

  def hyperv?
    physical_host = registry_getvaldata('HKLM\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters', 'PhysicalHostNameFullyQualified')
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

    sfmsvals = registry_enumkeys('HKLM\\SOFTWARE\\Microsoft')
    if sfmsvals
      return true if sfmsvals.include?('Hyper-V')
      return true if sfmsvals.include?('VirtualMachine')
    end

    return true if registry_getvaldata('HKLM\\HARDWARE\\DESCRIPTION\\System', 'SystemBiosVersion') =~ /vrtual/i

    %w[HKLM\\HARDWARE\\ACPI\\FADT HKLM\\HARDWARE\\ACPI\\RSDT].each do |key|
      srvvals = registry_enumkeys(key)
      return true if srvvals && srvvals.include?('VRTUAL')
    end

    %w[vmicexchange vmicheartbeat vmicshutdown vmicvss].each do |service|
      return true if service_exists?(service)
    end

    key_path = 'HKLM\\HARDWARE\\DESCRIPTION\\System'
    system_bios_version = registry_getvaldata(key_path, 'SystemBiosVersion')
    return true if system_bios_version && system_bios_version.include?('Hyper-V')

    key_path = 'HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0'
    return true if registry_getvaldata(key_path, 'Identifier') =~ /Msft    Virtual Disk    1.0/i

    false
  end

  def vmware?
    %w[vmdebug vmmouse VMTools VMMEMCTL tpautoconnsvc tpvcgateway vmware wmci vmx86].each do |service|
      return true if service_exists?(service)
    end

    return true if registry_getvaldata('HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS', 'SystemManufacturer') =~ /vmware/i
    return true if registry_getvaldata('HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0', 'Identifier') =~ /vmware/i
    return true if registry_getvaldata('HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0', 'Identifier') =~ /vmware/i
    return true if registry_getvaldata('HKLM\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000', 'DriverDesc') =~ /cl_vmx_svga|VMWare/i

    vmwareprocs = [
      'vmtoolsd.exe',
      'vmwareservice.exe',
      'vmwaretray.exe',
      'vmwareuser.exe'
    ]
    get_processes.each do |x|
      vmwareprocs.each do |p|
        return true if p == x['name'].downcase
      end
    end

    false
  end

  def virtualpc?
    %w[vpc-s3 vpcbus vpcuhub msvmmouf].each do |service|
      return true if service_exists?(service)
    end

    vpcprocs = [
      'vpcmap.exe',
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

    %w[HKLM\\HARDWARE\\ACPI\\DSDT HKLM\\HARDWARE\\ACPI\\FADT HKLM\\HARDWARE\\ACPI\\RSDT].each do |key|
      srvvals = registry_enumkeys(key)
      return true if srvvals && srvvals.include?('VBOX__')
    end

    for i in 0..2 do
          return true if registry_getvaldata("HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port #{i}0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", 'Identifier') =~ /vbox/i
    end

    return true if registry_getvaldata('HKLM\\HARDWARE\\DESCRIPTION\\System', 'SystemBiosVersion') =~ /vbox/i
    return true if registry_getvaldata('HKLM\\HARDWARE\\DESCRIPTION\\System', 'VideoBiosVersion') =~ /virtualbox/i
    return true if registry_getvaldata('HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS', 'SystemProductName') =~ /virtualbox/i

    %w[VBoxMouse VBoxGuest VBoxService VBoxSF VBoxVideo].each do |service|
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

    %w[HKLM\\HARDWARE\\ACPI\\DSDT HKLM\\HARDWARE\\ACPI\\FADT HKLM\\HARDWARE\\ACPI\\RSDT].each do |key|
      srvvals = registry_enumkeys(key)
      return true if srvvals && srvvals.include?('Xen')
    end

    %w[xenevtchn xennet xennet6 xensvc xenvdb].each do |service|
      return true if service_exists?(service)
    end

    return true if registry_getvaldata('HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS', 'SystemProductName') =~ /xen/i

    false
  end

  def qemu?
    key_path = 'HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0'
    return true if registry_getvaldata(key_path, 'Identifier') =~ /qemu|virtio/i

    key_path = 'HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0'
    return true if registry_getvaldata(key_path, 'ProcessorNameString') =~ /qemu/i

    return true if registry_getvaldata('HKLM\\HARDWARE\\DESCRIPTION\\System', 'SystemBiosVersion') =~ /qemu/i
    return true if registry_getvaldata('HKLM\\HARDWARE\\DESCRIPTION\\System', 'VideoBiosVersion') =~ /qemu/i
    return true if registry_getvaldata('HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS', 'SystemManufacturer') =~ /qemu/i

    %w[HKLM\\HARDWARE\\ACPI\\DSDT HKLM\\HARDWARE\\ACPI\\FADT HKLM\\HARDWARE\\ACPI\\RSDT].each do |key|
      srvvals = registry_enumkeys(key)
      return true if srvvals && srvvals.include?('BOCHS_')
    end

    false
  end

   def parallels?
    return true if registry_getvaldata('HKLM\\HARDWARE\\DESCRIPTION\\System', 'SystemBiosVersion') =~ /parallels/i
    return true if registry_getvaldata('HKLM\\HARDWARE\\DESCRIPTION\\System', 'VideoBiosVersion') =~ /parallels/i

    false
  end

  def joesandbox?
    vpcprocs = [
      'joeboxcontrol.exe',
      'joeboxserver.exe'
    ]
    get_processes.each do |x|
      vpcprocs.each do |p|
        return true if p == x['name'].downcase
      end
    end

    key_path = 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion'
    return true if registry_getvaldata(key_path, 'ProductId') == '55274-640-2673064-23950'
    key_path = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
    return true if registry_getvaldata(key_path, 'ProductId') == '55274-640-2673064-23950'

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
      report_vm('Qemu/KVM')
    elsif parallels?
      report_vm('Parallels')
    elsif joesandbox?
      report_vm('JoeSandbox')
    else
      print_status('The target appears to be a Physical Machine')
    end
  end
end
