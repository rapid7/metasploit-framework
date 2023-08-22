##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System
  include Msf::Post::Process

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Linux Gather Virtual Environment Detection',
        'Description' => %q{
          This module attempts to determine whether the system is running
          inside of a virtual environment and if so, which one. This
          module supports detection of Hyper-V, VMWare, VirtualBox, Xen,
          and QEMU/KVM.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform' => [ 'linux' ],
        'SessionTypes' => [ 'shell', 'meterpreter' ]
      )
    )
  end

  # Run Method for when run command is issued
  def run
    print_status('Gathering System info ....')
    vm = nil
    dmi_info = nil

    if is_root?
      dmi_info = cmd_exec('/usr/sbin/dmidecode')
    end

    # Check DMi Info
    if dmi_info
      case dmi_info
      when /microsoft corporation/i
        vm = 'MS Hyper-V'
      when /vmware/i
        vm = 'VMware'
      when /virtualbox/i
        vm = 'VirtualBox'
      when /qemu/i
        vm = 'Qemu/KVM'
      when /domu/i
        vm = 'Xen'
      end
    end

    # Check kernel modules
    if !vm
      loaded_modules = read_file('/proc/modules')
      if !loaded_modules
        loaded_modules = cmd_exec('/sbin/lsmod').to_s
      end

      case loaded_modules.gsub("\n", ' ')
      when /vboxsf|vboxguest|vboxvideo|vboxvideo_drv|vboxdrv/i
        vm = 'VirtualBox'
      when /vmw_ballon|vmxnet|vmw/i
        vm = 'VMware'
      when /xen-vbd|xen-vnif|xen_netfront|xen_blkfront/
        vm = 'Xen'
      when /virtio_pci|virtio_net|virtio_blk|virtio_console|virtio_scsi|virtio_balloon|virtio_input|virtio-gpu|virtio-rng|virtio_dma_buf|virtio_mmio|virtio_pmem|virtio_snd/
        vm = 'Qemu/KVM'
      when /hv_vmbus|hv_blkvsc|hv_netvsc|hv_utils|hv_storvsc|hv_boot|hv_balloon|hyperv_keyboard|hid_hyperv|hyperv_fb/
        vm = 'MS Hyper-V'
      end
    end

    # Check SCSI Driver
    if !vm
      proc_scsi = read_file('/proc/scsi/scsi')
      if proc_scsi
        case proc_scsi.gsub("\n", ' ')
        when /vmware/i
          vm = 'VMware'
        when /vbox/i
          vm = 'VirtualBox'
        end
      end
    end

    # Check IDE Devices
    if !vm
      case cmd_exec('cat /proc/ide/hd*/model')
      when /vbox/i
        vm = 'VirtualBox'
      when /vmware/i
        vm = 'VMware'
      when /qemu/i
        vm = 'Qemu/KVM'
      when /virtual [vc]d/i
        vm = 'Hyper-V/Virtual PC'
      end
    end

    # identity Xen block Device Root
    if !vm
      proc_mounts = read_file('/proc/mounts')
      if proc_mounts
        case proc_mounts
        when %r{/dev/xvd.* / }
          vm = 'Xen'
        end
      end
    end

    # Check system vendor
    if !vm
      sys_vendor = read_file('/sys/class/dmi/id/sys_vendor')
      if sys_vendor
        case sys_vendor.gsub("\n", ' ')
        when /qemu/i
          vm = 'Qemu'
        when /vmware/i
          vm = 'VMWare'
        when /xen/i
          vm = 'Xen'
        when /microsoft/i
          vm = 'Hyper-V'
        end
      end
    end

    # Check using lspci
    if !vm
      case get_sysinfo[:distro]
      when /oracle|centos|suse|redhat|mandrake|slackware|fedora/i
        lspci_data = cmd_exec('/sbin/lspci')
      when /debian|ubuntu/
        lspci_data = cmd_exec('/usr/bin/lspci')
      else
        lspci_data = cmd_exec('lspci')
      end

      case lspci_data.to_s.gsub("\n", ' ')
      when /vmware/i
        vm = 'VMware'
      when /virtualbox/i
        vm = 'VirtualBox'
      end
    end

    # Check Product Name
    if !vm
      product_name = read_file('/sys/class/dmi/id/product_name')
      if product_name
        case product_name.gsub("\n", ' ')
        when /vmware/i
          vm = 'VMware'
        when /virtualbox/i
          vm = 'VirtualBox'
        when /xen/i
          vm = 'Xen'
        when /KVM/i
          vm = 'KVM'
        when /oracle/i
          vm = 'Oracle Corporation'
        end
      end
    end

    # Check BIOS Name
    if !vm
      bios_vendor = read_file('/sys/devices/virtual/dmi/id/bios_vendor')
      if bios_vendor
        case bios_vendor.gsub("\n", ' ')
        when /^xen/i
          vm = 'Xen'
        end
      end
    end

    # Check cpuinfo
    if !vm
      cpuinfo = read_file('/proc/cpuinfo')
      if cpuinfo
        case cpuinfo.gsub("\n", ' ')
        when /qemu virtual cpu|emulated by qemu|KVM processor/i
          vm = 'Qemu/KVM'
        end
      end
    end

    # Check Xen devices
    if !vm
      xen_capabilities = read_file('/sys/hypervisor/uuid')
      if xen_capabilities
        if ! xen_capabilities.include? '00000000-0000-0000-0000-000000000000'
          vm = 'Xen'
        end
      end
    end

    # Check Processes
    if !vm
      get_processes do |process|
        case process['name']
        when /hv_vss_daemon|hv_kvp_daemon|hv_fcopy_daemon/i
          vm = 'MS Hyper-V'
        end
      end
    end

    # Check dmesg Output
    if !vm
      dmesg = cmd_exec('dmesg')
      case dmesg
      when /vboxbios|vboxcput|vboxfacp|vboxxsdt|vbox cd-rom|vbox harddisk/i
        vm = 'VirtualBox'
      when /vmware virtual ide|vmware pvscsi|vmware virtual platform/i
        vm = 'VMware'
      when /xen_mem|xen-vbd/i
        vm = 'Xen'
      when /qemu virtual cpu version/i
        vm = 'Qemu/KVM'
      when %r{/dev/vmnet}
        vm = 'VMware'
      end
    end

    if vm
      print_good("This appears to be a '#{vm}' virtual machine")
      report_virtualization(vm)
    else
      print_status('This does not appear to be a virtual machine')
    end
  end
end
