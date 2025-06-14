# -*- coding: binary -*-
module Msf
class Post
module Solaris
module System
  include ::Msf::Post::Common
  include ::Msf::Post::File
  include ::Msf::Post::Unix

  #
  # Returns a Hash containing Distribution Name, Version and Kernel
  # Information
  #
  def get_sysinfo
    system_data = {}
    kernel_version = cmd_exec("uname -a")
    version = read_file("/etc/release").split("\n")[0].strip
    system_data[:version] = version
    system_data[:kernel] = kernel_version
    system_data[:hostname] = kernel_version.split(" ")[1]
    host_info = {
      :host => rhost,
      :os_name => 'Solaris',
      :name => system_data[:hostname]
    }
    # Test cases for these can be found here:
    #    http://rubular.com/r/MsGuhp89F0
    #    http://rubular.com/r/DWKG0jpPCk
    #    http://rubular.com/r/EjiIa1RFxB
    if /(?<OS>(?<!Open|Oracle )Solaris).+s2?(?<major>\d?\d)[x|s]?(_u)(?<minor>\d?\d)/ =~ system_data[:version]
      host_info[:os_flavor] = "#{major}.#{minor}"
    elsif /(?<OS>Oracle Solaris) (?<major>\d\d)\.(?<minor>\d?\d)/ =~ system_data[:version]
      host_info[:os_flavor] = "#{major}.#{minor}"
    elsif /(?<OS>OpenSolaris|OpenIndiana [\w]+) (?<major>\d\d\d\d)\.(?<minor>\d\d)/ =~ system_data[:version]
      host_info[:os_flavor] = "#{major}.#{minor}"
    end
    report_host(host_info)
    return system_data
  end

  #
  # Gathers all SUID files on the filesystem.
  # NOTE: This uses the Linux `find` command. It will most likely take a while to get all files.
  # Consider specifying a more narrow find path.
  # @param findpath The path on the system to start searching
  # @return [Array]
  def get_suid_files(findpath = '/')
    out = cmd_exec("find #{findpath} -perm -4000 -print -xdev").to_s.split("\n")
    out.delete_if {|i| i.include?'Permission denied'}
  rescue
    raise "Could not retrieve all SUID files"
  end

  #
  # Gets the $PATH environment variable
  #
  def get_path
    cmd_exec('echo $PATH').to_s
  rescue
    raise "Unable to determine path"
  end

  #
  # Gets basic information about the system's CPU.
  # @return [Hash]
  #
  def get_cpu_info
    info = {}
    orig = cmd_exec('kstat -m cpu_info -p').to_s
    cpuinfo = orig.split("\n")
    # This is probably a more platform independent way to parse the results (compared to splitting and assigning preset indices to values)
    cpuinfo.each do |l|
      info[:speed_mhz]   = l.split(':')[3].split("\t")[1].to_i if l.include? 'clock_MHz'
      info[:product]     = l.split(':')[3].split("\t")[1]      if l.include? 'brand'
      info[:vendor]      = l.split(':')[3].split("\t")[1]      if l.include? 'vendor_id'
      info[:cores]       = l.split(':')[3].split("\t")[1].to_i if l.include? 'ncore_per_chip'
    end
    return info
  rescue
    raise "Could not get CPU information"
  end

  #
  # Gets the hostname of the system
  # @return [String]
  #
  def get_hostname
    cmd_exec('uname -n').to_s
  rescue
    raise 'Unable to retrieve hostname'
  end

  #
  # Gets the name of the current shell
  # @return [String]
  #
  def get_shell_name
    psout = cmd_exec('ps -p $$').to_s
    psout.split("\n").last.split(' ')[3]
  rescue
    raise 'Unable to gather shell name'
  end

  #
  # Checks if the system has gcc installed
  # @return [Boolean]
  #
  def has_gcc?
    # /usr/sfw/bin - default gcc path on some systems
    # /opt/sfw/bin - default gcc path for gcc package
    # /opt/csw/bin - default gcc path for OpenCSW gcc package
    command_exists?('gcc') || command_exists?('/usr/sfw/bin/gcc') || command_exists?('/opt/sfw/bin/gcc') || command_exists?('/opt/csw/bin/gcc')
  rescue
    raise 'Unable to check for gcc'
  end

  #
  # Gets the mount point of `filepath`
  # @param [String] filepath The filepath to get the mount point
  # @return [String]
  #
  def get_mount_path(filepath)
    cmd_exec("df \"#{filepath}\" | tail -1").split(' ')[0]
  rescue
    raise "Unable to get mount path of #{filepath}"
  end


end # System
end # Solaris
end # Post
end # Msf
