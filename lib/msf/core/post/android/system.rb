# -*- coding: binary -*-

require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/unix'

module Msf
class Post
module Android
module System

  include Msf::Post::Common
  include Msf::Post::File

  # Returns system information from build.prop.
  #
  # @return [Hash] System information.
  def get_build_prop
    sys_data   = {}
    build_prop = cmd_exec('cat /system/build.prop')

    return sys_data if build_prop.blank?

    build_prop.scan(/(.+)=(.+)/i).collect {|e| Hash[*e]}.each do |setting|
      sys_data.merge!(setting)
    end

    return sys_data
  end

end ; end ; end ; end