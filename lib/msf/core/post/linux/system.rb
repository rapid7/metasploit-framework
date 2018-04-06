# -*- coding: binary -*-
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/unix'

module Msf
class Post
module Linux
module System
  include ::Msf::Post::Common
  include ::Msf::Post::File
  include ::Msf::Post::Unix

  #
  # Returns a Hash containing Distribution Name, Version and Kernel Information
  #
  def get_sysinfo
    system_data = {}
    etc_files = cmd_exec("ls /etc").split()

    kernel_version = cmd_exec("uname -a")
    system_data[:kernel] = kernel_version

    # Debian
    if etc_files.include?("debian_version")
      if kernel_version =~ /Ubuntu/
        version = read_file("/etc/issue").gsub(/\n|\\n|\\l/,'')
        system_data[:distro] = "ubuntu"
        system_data[:version] = version
      else
        version = read_file("/etc/issue").gsub(/\n|\\n|\\l/,'')
        system_data[:distro] = "debian"
        system_data[:version] = version
      end

    # Amazon
    elsif etc_files.include?("system-release")
      version = read_file("/etc/system-release").gsub(/\n|\\n|\\l/,'')
      system_data[:distro] = "amazon"
      system_data[:version] = version

    # Fedora
    elsif etc_files.include?("fedora-release")
      version = read_file("/etc/fedora-release").gsub(/\n|\\n|\\l/,'')
      system_data[:distro] = "fedora"
      system_data[:version] = version

    # Oracle Linux
    elsif etc_files.include?("enterprise-release")
      version = read_file("/etc/enterprise-release").gsub(/\n|\\n|\\l/,'')
      system_data[:distro] = "oracle"
      system_data[:version] = version

    # RedHat
    elsif etc_files.include?("redhat-release")
      version = read_file("/etc/redhat-release").gsub(/\n|\\n|\\l/,'')
      system_data[:distro] = "redhat"
      system_data[:version] = version

    # Arch
    elsif etc_files.include?("arch-release")
      version = read_file("/etc/arch-release").gsub(/\n|\\n|\\l/,'')
      system_data[:distro] = "arch"
      system_data[:version] = version

    # Slackware
    elsif etc_files.include?("slackware-version")
      version = read_file("/etc/slackware-version").gsub(/\n|\\n|\\l/,'')
      system_data[:distro] = "slackware"
      system_data[:version] = version

    # Mandrake
    elsif etc_files.include?("mandrake-release")
      version = read_file("/etc/mandrake-release").gsub(/\n|\\n|\\l/,'')
      system_data[:distro] = "mandrake"
      system_data[:version] = version

    #SuSE
    elsif etc_files.include?("SuSE-release")
      version = read_file("/etc/SuSE-release").gsub(/\n|\\n|\\l/,'')
      system_data[:distro] = "suse"
      system_data[:version] = version

    # Gentoo
    elsif etc_files.include?("gentoo-release")
      version = read_file("/etc/gentoo-release").gsub(/\n|\\n|\\l/,'')
      system_data[:distro] = "gentoo"
      system_data[:version] = version

    # Generic
    elsif etc_files.include?("issue")
      version = read_file("/etc/issue").gsub(/\n|\\n|\\l/,'')
      system_data[:distro] = "linux"
      system_data[:version] = version

    # Others, could be a mismatch like ssh_login to cisco device
    else
      system_data[:distro] = "linux"
      system_data[:version] = ''

    end
    return system_data
  end

  #
  # Returns all listening services along with their ports
  # @param portsonly Return the listening ports without their associated service
  # @return [Hash]
  # 
  def get_listening_services(portsonly = false)
    services = {}
    begin
      lines = cmd_exec('netstat -tulpn | wc -l')
      cmd = "netstat -tulpn | tail -n #{lines - 2} | awk '{print $7}'"
      cmd << " | cut -f1 -d '/'" if portsonly
      full = cmd_exec(cmd)
      full.delete!(':') # Only happens when getting services

      if portsonly
        ports = []
        full.split("\n").each do |p|
          ports << p
        end
        ports
      else
        full.split("\n").each do |s|
          split = s.split('/')
          services[:"#{split[0]}"] = split[1]
        end
      end

      services
    rescue
      raise 'Could not gather listening ports'
    end
  end

  #
  # Gathers all SUID files on the filesystem.
  # NOTE: This uses the Linux `find` command. It will most likely take a while to get all files.
  # Consider specifying a more narrow find path.
  # @param findpath The path on the system to start searching
  # @return [Array]
  def get_suid_files(findpath = '/')
    begin
      cmd_exec("find #{findpath} -perm -4000 -print").split("\n")
    rescue
      raise "Could not retrieve all SUID files"
    end
  end

  #
  # Gets the $PATH environment variable
  #
  def get_path
    begin
      cmd_exec('echo $PATH')
    rescue
      raise "Unable to determine path"
    end
  end

  def get_cpu_info
    info = {}
    begin
      cpuinfo = cmd_exec("lshw | grep -A9 '*-cpu' | tr -d '          '") # Holy hack
      # This is probably a more platform independent way to parse the results (compared to splitting and assigning preset indices to values)
      cpuinfo.split("\n").each do |l|
        info[:speed]   = l.split(':')[1] if l =~ /capacity:/
        info[:product] = l.split(':')[1] if l =~ /product:/
        info[:vendor]  = l.split(':')[1] if l =~ /vendor:/
      end
      info
    rescue
      raise "Could not get CPU information"
    end
  end

end # System
end # Linux
end # Post
end # Msf
