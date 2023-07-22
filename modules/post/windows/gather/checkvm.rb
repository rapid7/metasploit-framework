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
  # the processes running and returns true upon a match. 
  # casecmp? provides matching independent of case 
  def procs?(vm_processes)
    vm_processes.each do |x|
      @processes.each do |p|
        return true if p['name'].casecmp?(x) 
      end 
    end 
    false
  end 

  # This method is currently called in vmware? but should be called # in the first method that enumerates processes in run, thus if the order of
  # the methods changes in the future ie. if vpcprocs? comes before vmware? in
  # in the if/elsif block in run the processes call should be removed from
  # vmware? and places inside run. 

  # Another option would be to call processes before executing the long 
  # if/elsif block in run but I found that would be unecessary if the call
  # exits at a method that doesn't enumerate processes

  # Returns list of running processes and store them in @processes instance variable.
  def processes
    @processes = get_processes
  end 

  # loops over a list of vm services and compares them to the list of running
  # services. 
  def services?(vm_services)
    vm_services.each do |srvc|
      return true if service_exists?(srvc)
    end 
    false
  end 

  # previously @services was nil, making it an empty list as default helps
  # remove an uneccesarry && call in service_exists? that was implimented
  # in order to avoid a no_method error when calling .include? on a nil

  def get_services
    @services = registry_enumkeys('HKLM\\SYSTEM\\ControlSet001\\Services')
    @services = [] if @services.nil?
    @services
  end

  def service_exists?(service)
    @services.include?(service)
  end

  # loops over a list of keys and sees if vm_key is included within them
  def key?(keys, vm_key)
    keys.each do |k|
      srvals = get_serval(k)
      return true if srvals.include?(vm_key)
    end 
  end 

  def get_srval(key)
    srvals = registry_enumkeys(k)
    srvals = [] if srvals.nil?
    srvals
  end 

  # returns true if regval matches a regex
  def regval_match?(k,v,rgx)
    return true if get_regval_str(k, v) =~ rgx
    false 
  end

  def regval_eql?(k,v,eq)
    get_regval_str(k,v) == eq
  end 

  def get_regval_str(key, valname)
    ret = registry_getvaldata(key, valname)
    if ret.kind_of?(Array)
      ret = ret.join
    end
    ret
  end

  def parallels?
    @system_bios_version = get_regval_str('HKLM\\HARDWARE\\DESCRIPTION\\System', 'SystemBiosVersion')
    
    @video_bios_version =  get_regval_str('HKLM\\HARDWARE\\DESCRIPTION\\System'
    , 'VideoBiosVersion')

    return true if @system_bios_version =~ /parallels/i || @video_bios_version =~ /parallels/i

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

    return true if @system_bios_version =~ /vrtual/i

    keys = %w[HKLM\\HARDWARE\\ACPI\\FADT HKLM\\HARDWARE\\ACPI\\RSDT]

    return true if key?(keys, 'VRTUAL')
    
    hyperv_services = %w[vmicexchange vmicheartbeat vmicshutdown vmicvss]

    return true if services?(hyperv_services)

    return true if @system_bios_version == 'Hyper-V'

    @scsi_port_0 = get_regval_str('HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0', 'Identifier')

    return true if @scsi_port_0 =~ /Msft    Virtual Disk    1.0/i) 

    false
  end

  def vmware?
    vmware_services = %w[vmdebug vmmouse VMTools VMMEMCTL tpautoconnsvc 
      tpvcgateway vmware wmci vmx86]

    return true if services?(vmware_services)

    # list of lists containg registers keypath, a value and the regex to match 
    # against

    @system_manufacturer = get_regval_str('HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS', 
        'SystemManufacturer')

    return true if @system_manufacturer =~ /vmware/i

    @scsi_port_1 = get_regval_str('HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0', 
        'Identifier' )

    return true if @scsi_port_1 =~ /vmware/i

    return true if regval_match?(
      'HKLM\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000',
      'DriverDesc',
      /cl_vmx_svga|VMWare/i
      )

    processes

    vmwareprocs = [
      'vmtoolsd.exe',
      'vmwareservice.exe',
      'vmwaretray.exe',
      'vmwareuser.exe'
    ]

    return true if procs?(vmwareprocs)
    
    false
  end

  def virtualbox?
    vboxprocs = [
      'vboxservice.exe',
      'vboxtray.exe'
    ]

    return true if procs?(vboxprocs)

    keys = %w[HKLM\\HARDWARE\\ACPI\\DSDT HKLM\\HARDWARE\\ACPI\\FADT HKLM\\HARDWARE\\ACPI\\RSDT]

    return true if key?(keys, 'VBOX__')

    for i in 0..2 do
      return true if regval_match?(
        "HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port #{i}0\\Scsi Bus 0\\Target
         Id 0\\Logical Unit Id 0",
        'Identifier',
         /vbox/i )    
    end

    return true if @system_bios_version =~ /vbox/i || @video_bios_version =~ /virtualbox/i
     

    @system_product_name = get_regval_str('HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS','SystemProductName',)

    return true if @system_product_name =~ /virtualbox/i

    vbox_services = %w[VBoxMouse VBoxGuest VBoxService VBoxSF VBoxVideo]

    return true if services?(vbox_services)

    false
  end

  def xen?
    xenprocs = [
      'xenservice.exe'
    ]

    return true if procs?(xenprocs)

    keys = %w[HKLM\\HARDWARE\\ACPI\\DSDT HKLM\\HARDWARE\\ACPI\\FADT HKLM\\HARDWARE\\ACPI\\RSDT]

    return true if key?(keys,'Xen')

    xen_services = %w[xenevtchn xennet xennet6 xensvc xenvdb]

    return true if services?(xen_services)

    return true if @system_product_name =~ /xen/i

    false
  end

  def qemu?
    return true if @system_bios_version =~ /qemu/i || @video_bios_version =~ /qemu/i

    return true if @scsi_port_0 =~ /qemu|virtio/i

   
      [
        
      ],
    ]
   
    return true if @system_manufacturer =~ /qemu/i
    
    return true if regval_match?(
      'HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0',
      'ProcessorNameString',
      /qemu/i)

    keys = %w[HKLM\\HARDWARE\\ACPI\\DSDT HKLM\\HARDWARE\\ACPI\\FADT HKLM\\HARDWARE\\ACPI\\RSDT]

    return true if key?(keys, 'BOCHS_')

    false
  end

  def parallels?

    @bios_version = get_regval_str('HKLM\\HARDWARE\\DESCRIPTION\\System', 'SystemBiosVersion')
    return true if @bios_version =~ /parallels/i
    
    @video_bios_version =  get_regval_str('HKLM\\HARDWARE\\DESCRIPTION\\System'
    , 'VideoBiosVersion')
    return true if @video_bios_version =~ /parallels/i

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