# -*- coding: binary -*-
require 'msf/core/post/common'

module Msf
class Post
module Solaris
module Kernel
  include ::Msf::Post::Common

  #
  # Returns uname output
  #
  # @return [String]
  #
  def uname(opts='-a')
    cmd_exec("uname #{opts}").to_s.strip
  rescue
    raise "Failed to run uname #{opts}"
  end

  #
  # Returns the kernel release
  #
  # @return [String]
  #
  def kernel_release
    uname('-r')
  end

  #
  # Returns the kernel version
  #
  # @return [String]
  #
  def kernel_version
    uname('-v')
  end

  #
  # Returns the kernel name
  #
  # @return [String]
  #
  def kernel_name
    uname('-s')
  end

  #
  # Returns the kernel hardware
  #
  # @return [String]
  #
  def kernel_hardware
    uname('-m')
  end

end # Kernel
end # Linux
end # Post
end # Msf
