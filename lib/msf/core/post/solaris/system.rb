# -*- coding: binary -*-
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/unix'

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
    return system_data
  end

end # System
end # Solaris
end # Post
end # Msf
