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
    else

      # Others
      version = read_file("/etc/issue").gsub(/\n|\\n|\\l/,'')
      system_data[:distro] = "linux"
      system_data[:version] = version
    end
    return system_data
  end


end # System
end # Linux
end # Post
end # Msf
