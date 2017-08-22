##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System


  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Linux Gather Virtual Environment Detection',
        'Description'   => %q{
          This module attempts to determine whether the system is running
          inside of a virtual environment and if so, which one. This
          module supports detection of Hyper-V, VMWare, VirtualBox, Xen,
          and QEMU/KVM.},
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform'      => [ 'linux' ],
        'SessionTypes'  => [ 'shell', 'meterpreter' ]
      ))
  end

  # Run Method for when run command is issued
  def run
    print_status("Gathering System info ....")
    vm = nil
    dmi_info = nil
    ls_pci_data = nil

    if is_root?
      dmi_info = cmd_exec("/usr/sbin/dmidecode")
    end

    # Check DMi Info
    if dmi_info
      case dmi_info
      when /microsoft corporation/i
        vm = "MS Hyper-V"
      when /vmware/i
        vm = "VMware"
      when /virtualbox/i
        vm = "VirtualBox"
      when /qemu/i
        vm = "Qemu/KVM"
      when /domu/i
        vm = "Xen"
      end
    end

    # Check Modules
    if not vm
      loaded_modules = cmd_exec("/sbin/lsmod")
      case loaded_modules.to_s.gsub("\n", " ")
      when /vboxsf|vboxguest/i
        vm = "VirtualBox"
      when /vmw_ballon|vmxnet|vmw/i
        vm = "VMware"
      when /xen-vbd|xen-vnif/
        vm = "Xen"
      when /virtio_pci|virtio_net/
        vm = "Qemu/KVM"
      when /hv_vmbus|hv_blkvsc|hv_netvsc|hv_utils|hv_storvsc/
        vm = "MS Hyper-V"
      end
    end

    # Check SCSI Driver
    if not vm
      proc_scsi = read_file("/proc/scsi/scsi") rescue ""
      case proc_scsi.gsub("\n", " ")
      when /vmware/i
        vm = "VMware"
      when /vbox/i
        vm = "VirtualBox"
      end
    end

    # Check IDE Devices
    if not vm
      case cmd_exec("cat /proc/ide/hd*/model")
      when /vbox/i
        vm = "VirtualBox"
      when /vmware/i
        vm = "VMware"
      when /qemu/i
        vm = "Qemu/KVM"
      when /virtual [vc]d/i
        vm = "Hyper-V/Virtual PC"
      end
    end

    # Check using lspci
    if not vm
      case get_sysinfo[:distro]
      when /oracle|centos|suse|redhat|mandrake|slackware|fedora/i
        lspci_data = cmd_exec("/sbin/lspci")
      when /debian|ubuntu/
        lspci_data = cmd_exec("/usr/bin/lspci")
      else
        lspci_data = cmd_exec("lspci")
      end

      case lspci_data.to_s.gsub("\n", " ")
      when /vmware/i
        vm = "VMware"
      when /virtualbox/i
        vm = "VirtualBox"
      end
    end

    # Xen bus check
    if not vm
      if cmd_exec("ls -1 /sys/bus").to_s.split("\n").include?("xen")
        vm = "Xen"
      end
    end

    # Check using lscpu
    if not vm
      case cmd_exec("lscpu")
      when /Xen/i
        vm = "Xen"
      when /KVM/i
        vm = "KVM"
      when /Microsoft/i
        vm = "MS Hyper-V"
      end
    end

    # Check dmesg Output
    if not vm
      dmesg = cmd_exec("dmesg")
      case dmesg
      when /vboxbios|vboxcput|vboxfacp|vboxxsdt|vbox cd-rom|vbox harddisk/i
        vm = "VirtualBox"
      when /vmware virtual ide|vmware pvscsi|vmware virtual platform/i
        vm = "VMware"
      when /xen_mem|xen-vbd/i
        vm =  "Xen"
      when /qemu virtual cpu version/i
        vm = "Qemu/KVM"
      when /\/dev\/vmnet/
        vm = "VMware"
      end
    end

    if vm
      print_good("This appears to be a '#{vm}' virtual machine")
      report_virtualization(vm)
    else
      print_status("This does not appear to be a virtual machine")
    end

  end
end
