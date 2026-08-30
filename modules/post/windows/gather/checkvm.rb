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
          module supports detection of Hyper-V, VMWare, VirtualBox, Xen, QEMU,
          and Parallels.
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

  # enumerates through a list of VM signature processes and compares them to
  # the processes running, returns true upon a match.
  def processes_exist?(vm_processes)
    vm_processes.each do |x|
      @processes.each do |p|
        return true if p['name'].casecmp?(x)
      end
    end
    false
  end

  # loops over a list of services that are known to be signatures of vm's and
  # compares them to the list of running services.
  def services_exist?(vm_services)
    vm_services.each do |srvc|
      return true if service_exists?(srvc)
    end
    false
  end

  def service_exists?(service)
    @services.include?(service)
  end

  # registers relevant keys and stores them in a hash
  def register_keys(key_list)
    @keys = {}
    key_list.each do |k|
      srvals = get_srval(k)
      srvals = [] if srvals.nil?
      @keys.store(k, srvals)
    end
    @keys
  end

  # checks the values of the keys and compares them to vm_k
  def key_present?(vm_k)
    @keys.each_value do |v|
      return true if v.include?(vm_k)
    end
    false
  end

  def get_srval(key)
    srvals = registry_enumkeys(key)
    srvals = [] if srvals.nil?
    srvals
  end

  # returns true if regval matches a regex
  def regval_match?(key, val, rgx)
    return true if get_regval_str(key, val) =~ rgx

    false
  end

  # returns true if regval is eql to a string
  def regval_eql?(key, val, str)
    get_regval_str(key, val) == str
  end

  def get_regval_str(key, valname)
    ret = registry_getvaldata(key, valname)
    if ret.is_a?(Array)
      ret = ret.join
    end
    ret
  end

  def parallels?
    @system_bios_version = get_regval_str('HKLM\\HARDWARE\\DESCRIPTION\\System', 'SystemBiosVersion')

    @video_bios_version = get_regval_str('HKLM\\HARDWARE\\DESCRIPTION\\System', 'VideoBiosVersion')

    if @system_bios_version =~ /parallels/i || @video_bios_version =~ /parallels/i
      return true
    end

    false
  end

  def hyperv?
    physical_host = get_regval_str('HKLM\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters', 'PhysicalHostNameFullyQualified')

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
      %w[Hyper-V VirtualMachine].each do |vm|
        return true if sfmsvals.include?(vm)
      end
    end

    if @system_bios_version =~ /vrtual/i || @system_bios_version == 'Hyper-V'
      return true
    end

    keys = %w[HKLM\\HARDWARE\\ACPI\\FADT HKLM\\HARDWARE\\ACPI\\RSDT HKLM\\HARDWARE\\ACPI\\DSDT]

    register_keys(keys)

    return true if key_present?('VRTUAL')

    hyperv_services = %w[vmicexchange]

    return true if services_exist?(hyperv_services)

    false
  end

  def vmware?
    vmware_services = %w[
      vmdebug vmmouse VMTools VMMEMCTL tpautoconnsvc
      tpvcgateway vmware wmci vmx86
    ]

    return true if services_exist?(vmware_services)

    @system_manufacturer = get_regval_str('HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS',
                                          'SystemManufacturer')

    return true if @system_manufacturer =~ /vmware/i

    @scsi_port_1 = get_regval_str('HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0',
                                  'Identifier')

    return true if @scsi_port_1 =~ /vmware/i

    return true if regval_match?(
      'HKLM\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000',
      'DriverDesc',
      /cl_vmx_svga|VMWare/i
    )

    vmwareprocs = [
      'vmtoolsd.exe',
      'vmwareservice.exe',
      'vmwaretray.exe',
      'vmwareuser.exe'
    ]

    return true if processes_exist?(vmwareprocs)

    false
  end

  def virtualbox?
    vboxprocs = [
      'vboxservice.exe',
      'vboxtray.exe'
    ]

    vbox_srvcs = %w[VBoxMouse VBoxGuest VBoxService VBoxSF VBoxVideo]

    if services_exist?(vbox_srvcs) || processes_exist?(vboxprocs)
      return true
    end

    return true if key_present?('VBOX__')

    for i in 0..2 do
      return true if regval_match?(
        "HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port #{i}0\\Scsi Bus 0\\Target
         Id 0\\Logical Unit Id 0",
        'Identifier',
        /vbox/i
      )
    end

    return true if @system_bios_version =~ /vbox/i || @video_bios_version =~ /virtualbox/i

    @system_product_name = get_regval_str('HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS', 'SystemProductName')

    return true if @system_product_name =~ /virtualbox/i

    false
  end

  def xen?
    xenprocs = [
      'xenservice.exe'
    ]

    xen_srvcs = %w[xenevtchn xennet xennet6 xensvc xenvdb]

    if processes_exist?(xenprocs) || services_exist?(xen_srvcs)
      return true
    end

    return true if key_present?('Xen')

    return true if @system_product_name =~ /xen/i

    false
  end

  def qemu?
    if @system_bios_version =~ /qemu/i || @video_bios_version =~ /qemu/i
      return true
    end

    if @scsi_port_0 =~ /qemu|virtio/i || @system_manufacturer =~ /qemu/i
      return true
    end

    return true if regval_match?(
      'HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0',
      'ProcessorNameString',
      /qemu/i
    )

    return true if key_present?('BOCHS_')

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
    @processes = get_processes
    @processes = [] if @processes.nil?

    @services = registry_enumkeys('HKLM\\SYSTEM\\ControlSet001\\Services')
    @services = [] if @services.nil?

    if parallels?
      report_vm('Parallels')
    elsif hyperv?
      report_vm('Hyper-V')
    elsif vmware?
      report_vm('VMware')
    elsif virtualbox?
      report_vm('VirtualBox')
    elsif xen?
      report_vm('Xen')
    elsif qemu?
      report_vm('Qemu/KVM')
    else
      print_status('The target appears to be a Physical Machine')
    end
  end
end
