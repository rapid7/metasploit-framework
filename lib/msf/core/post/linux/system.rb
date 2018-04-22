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
  # Gathers all SUID files on the filesystem.
  # NOTE: This uses the Linux `find` command. It will most likely take a while to get all files.
  # Consider specifying a more narrow find path.
  # @param findpath The path on the system to start searching
  # @return [Array]
  def get_suid_files(findpath = '/')
    cmd_exec("find #{findpath} -perm -4000 -print -xdev").to_s.split("\n")
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
    orig = cmd_exec("cat /proc/cpuinfo").to_s
    cpuinfo = orig.split("\n\n")[0]
    # This is probably a more platform independent way to parse the results (compared to splitting and assigning preset indices to values)
    cpuinfo.split("\n").each do |l|
      info[:speed_mhz]   = l.split(': ')[1].to_i if l.include? 'cpu MHz'
      info[:product]     = l.split(': ')[1]      if l.include? 'model name'
      info[:vendor]      = l.split(': ')[1]      if l.include? 'vendor_id'
    end
    info[:cores] = orig.split("\n\n").size
    info
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
    command_exists? 'gcc'
  rescue
    raise 'Unable to check for gcc'
  end

  #
  # Checks if the `cmd` is installed on the system
  # @return [Boolean]
  #
  def command_exists?(cmd)
    cmd_exec("command -v #{cmd} && echo true").to_s.include? 'true'
  rescue
    raise "Unable to check if command `#{cmd}` exists"
  end

  #
  # Gets the process id(s) of `program`
  # @return [Array]
  #
  def pidof(program)
    pids = []
    full = cmd_exec('ps aux').to_s
    full.split("\n").each do |pid|
      pids << pid.split(' ')[1].to_i if pid.include? program
    end
    pids
  end

  #
  # Checks if `file_path` is mounted on a noexec mount point
  # @return [Boolean]
  #
  def noexec?(file_path)
    mount = cmd_exec('cat /proc/mounts').to_s
    mount_path = get_mount_path(file_path)
    mount.lines.each do |l|
      return true if l =~ Regexp.new("#{mount_path} (.*)noexec(.*)")
    end
    false
  rescue
    raise 'Unable to check for noexec volume'
  end

  #
  # Checks if `file_path` is mounted on a nosuid mount point
  # @return [Boolean]
  #
  def nosuid?(file_path)
    mount = cmd_exec('cat /proc/mounts').to_s
    mount_path = get_mount_path(file_path)
    mount.lines.each do |l|
      return true if l =~ Regexp.new("#{mount_path} (.*)nosuid(.*)")
    end
    false
  rescue
    raise 'Unable to check for nosuid volume'
  end

  #
  # Checks for protected hardlinks on the system
  # @return [Boolean]
  #
  def protected_hardlinks?
    read_file('/proc/sys/fs/protected_hardlinks').to_s.strip.eql? '1'
  rescue
    raise 'Could not determine protected_hardlinks status'
  end

  #
  # Checks for protected symlinks on the system
  # @return [Boolean]
  #
  def protected_symlinks?
    read_file('/proc/sys/fs/protected_symlinks').to_s.strip.eql? '1'
  rescue
    raise 'Could not determine protected_symlinks status'
  end

  #
  # Gets the version of glibc
  # @return [String]
  #
  def glibc_version
    raise 'glibc is not installed' unless command_exists? 'ldd'
    cmd_exec('ldd --version').scan(/^ldd\s+\(.*\)\s+([\d.]+)/).flatten.first
  rescue
    raise 'Could not determine glibc version'
  end

  #
  # Gets the mount point of `filepath`
  # @param [String] filepath The filepath to get the mount point
  # @return [String]
  #
  def get_mount_path(filepath)
    cmd_exec("df \"#{filepath}\" | tail -1").split(' ')[5]
  rescue
    raise "Unable to get mount path of #{filepath}"
  end


end # System
end # Linux
end # Post
end # Msf
