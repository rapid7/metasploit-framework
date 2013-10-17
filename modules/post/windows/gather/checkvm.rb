##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather Virtual Environment Detection',
      'Description'   => %q{
        This module attempts to determine whether the system is running
        inside of a virtual environment and if so, which one. This
        module supports detectoin of Hyper-V, VMWare, Virtual PC,
        VirtualBox, Xen, and QEMU.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  # Method for detecting if it is a Hyper-V VM
  def hypervchk(session)
    vm = false
    sfmsvals = registry_enumkeys('HKLM\SOFTWARE\Microsoft')
    if sfmsvals and sfmsvals.include?("Hyper-V")
      vm = true
    elsif sfmsvals and sfmsvals.include?("VirtualMachine")
      vm = true
    end
    if not vm
      if registry_getvaldata('HKLM\HARDWARE\DESCRIPTION\System','SystemBiosVersion') =~ /vrtual/i
        vm = true
      end
    end
    if not vm
      srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\FADT')
      if srvvals and srvvals.include?("VRTUAL")
        vm = true
      end
    end
    if not vm
      srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\RSDT')
      if srvvals and srvvals.include?("VRTUAL")
        vm = true
      end
    end
    if not vm
      srvvals = registry_enumkeys('HKLM\SYSTEM\ControlSet001\Services')
      if srvvals and srvvals.include?("vmicheartbeat")
        vm = true
      elsif srvvals and srvvals.include?("vmicvss")
        vm = true
      elsif srvvals and srvvals.include?("vmicshutdown")
        vm = true
      elsif srvvals and srvvals.include?("vmicexchange")
        vm = true
      end
    end
    if vm
      report_note(
        :host   => session,
        :type   => 'host.hypervisor',
        :data   => { :hypervisor => "MS Hyper-V" },
        :update => :unique_data
        )
      print_status("This is a Hyper-V Virtual Machine")
      return "MS Hyper-V"
    end
  end

  # Method for checking if it is a VMware VM
  def vmwarechk(session)
    vm = false
    srvvals = registry_enumkeys('HKLM\SYSTEM\ControlSet001\Services')
    if srvvals and  srvvals.include?("vmdebug")
      vm = true
    elsif srvvals and srvvals.include?("vmmouse")
      vm = true
    elsif srvvals and srvvals.include?("VMTools")
      vm = true
    elsif srvvals and srvvals.include?("VMMEMCTL")
      vm = true
    end
    if not vm
      if registry_getvaldata('HKLM\HARDWARE\DESCRIPTION\System\BIOS','SystemManufacturer') =~ /vmware/i
        vm = true
      end
    end
    if not vm
      key_path = 'HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0'
      if registry_getvaldata(key_path,'Identifier') =~ /vmware/i
        vm = true
      end
    end
    if not vm
      vmwareprocs = [
        "vmwareuser.exe",
        "vmwaretray.exe"
      ]
      session.sys.process.get_processes().each do |x|
        vmwareprocs.each do |p|
          if p == (x['name'].downcase)
            vm = true
          end
        end
      end
    end

    if vm
      report_note(
        :host   => session,
        :type   => 'host.hypervisor',
        :data   => { :hypervisor => "VMware" },
        :update => :unique_data
        )
      print_status("This is a VMware Virtual Machine")
      return "VMWare"
    end
  end

  # Method for checking if it is a Virtual PC VM
  def checkvrtlpc(session)
    vm = false
    vpcprocs = [
      "vmusrvc.exe",
      "vmsrvc.exe"
    ]
    session.sys.process.get_processes().each do |x|
      vpcprocs.each do |p|
        if p == (x['name'].downcase)
          vm = true
        end
      end
    end
    if not vm
      srvvals = registry_enumkeys('HKLM\SYSTEM\ControlSet001\Services')
      if srvvals and srvvals.include?("vpc-s3")
        vm = true
      elsif srvvals and srvvals.include?("vpcuhub")
        vm = true
      elsif srvvals and srvvals.include?("msvmmouf")
        vm = true
      end
    end
    if vm
      report_note(
        :host   => session,
        :type   => 'host.hypervisor',
        :data   => { :hypervisor => "VirtualPC" },
        :update => :unique_data
        )
      print_status("This is a VirtualPC Virtual Machine")
      return "VirtualPC"
    end
  end

  # Method for checking if it is a VirtualBox VM
  def vboxchk(session)
    vm = false
    vboxprocs = [
      "vboxservice.exe",
      "vboxtray.exe"
    ]
    session.sys.process.get_processes().each do |x|
      vboxprocs.each do |p|
        if p == (x['name'].downcase)
          vm = true
        end
      end
    end
    if not vm
      srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\DSDT')
      if srvvals and srvvals.include?("VBOX__")
        vm = true
      end
    end
    if not vm
      srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\FADT')
      if srvvals and srvvals.include?("VBOX__")
        vm = true
      end
    end
    if not vm
      srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\RSDT')
      if srvvals and srvvals.include?("VBOX__")
        vm = true
      end
    end
    if not vm
      key_path = 'HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0'
      if registry_getvaldata(key_path,'Identifier') =~ /vbox/i
        vm = true
      end
    end
    if not vm
      if registry_getvaldata('HKLM\HARDWARE\DESCRIPTION\System','SystemBiosVersion') =~ /vbox/i
        vm = true
      end
    end
    if not vm
      srvvals = registry_enumkeys('HKLM\SYSTEM\ControlSet001\Services')
      if srvvals and srvvals.include?("VBoxMouse")
        vm = true
      elsif srvvals and srvvals.include?("VBoxGuest")
        vm = true
      elsif srvvals and srvvals.include?("VBoxService")
        vm = true
      elsif srvvals and srvvals.include?("VBoxSF")
        vm = true
      end
    end
    if vm
      report_note(
        :host   => session,
        :type   => 'host.hypervisor',
        :data   => { :hypervisor => "VirtualBox" },
        :update => :unique_data
        )
      print_status("This is a Sun VirtualBox Virtual Machine")
      return "VirtualBox"
    end
  end

  # Method for checking if it is a Xen VM
  def xenchk(session)
    vm = false
    xenprocs = [
      "xenservice.exe"
    ]
    session.sys.process.get_processes().each do |x|
      xenprocs.each do |p|
        if p == (x['name'].downcase)
          vm = true
        end
      end
    end
    if not vm
      srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\DSDT')
      if srvvals and srvvals.include?("Xen")
        vm = true
      end
    end
    if not vm
      srvvals = registry_enumkeys('HARDWARE\ACPI\FADT')
      if srvvals and srvvals.include?("Xen")
        vm = true
      end
    end
    if not vm
      srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\RSDT')
      if srvvals and srvvals.include?("Xen")
        vm = true
      end
    end
    if not vm
      srvvals = registry_enumkeys('HKLM\SYSTEM\ControlSet001\Services')
      if srvvals and srvvals.include?("xenevtchn")
        vm = true
      elsif srvvals and srvvals.include?("xennet")
        vm = true
      elsif srvvals and srvvals.include?("xennet6")
        vm = true
      elsif srvvals and srvvals.include?("xensvc")
        vm = true
      elsif srvvals and srvvals.include?("xenvdb")
        vm = true
      end
    end
    if vm
      report_note(
        :host   => session,
        :type   => 'host.hypervisor',
        :data   => { :hypervisor => "Xen" },
        :update => :unique_data
        )
      print_status("This is a Xen Virtual Machine")
      return "Xen"
    end
  end

  def qemuchk(session)
    vm = false
    if not vm
      key_path = 'HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0'
      if registry_getvaldata(key_path,'Identifier') =~ /qemu/i
        print_status("This is a QEMU/KVM Virtual Machine")
        vm = true
      end
    end
    if not vm
      key_path = 'HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0'
      if registry_getvaldata(key_path,'ProcessorNameString') =~ /qemu/i
        print_status("This is a QEMU/KVM Virtual Machine")
        vm = true
      end
    end

    if vm
      report_note(
        :host   => session,
        :type   => 'host.hypervisor',
        :data   => { :hypervisor => "Qemu/KVM" },
        :update => :unique_data
        )
      return "Qemu/KVM"
    end
  end

  # run Method
  def run
    print_status("Checking if #{sysinfo['Computer']} is a Virtual Machine .....")
    found = hypervchk(session)
    found ||= vmwarechk(session)
    found ||= checkvrtlpc(session)
    found ||= vboxchk(session)
    found ||= xenchk(session)
    found ||= qemuchk(session)
    if found
      report_vm(found)
    else
      print_status("#{sysinfo['Computer']} appears to be a Physical Machine")
    end
  end

end
