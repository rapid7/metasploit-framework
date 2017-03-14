# -*- coding: binary -*-

require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/unix'

module Msf
class Post
module Android
module Priv

  include Msf::Post::Common

  public

  # Returns whether we are running as root or not.
  #
  # @return [Boolean] TrueClass if as root, otherwise FalseClass.
  def is_root?
    id = cmd_exec('id')
    uid = id.scan(/uid=(\d+)(.+)/).flatten.first
    if /^0$/ === uid
      return true
    else
      return false
    end
  end

  private

  def get_id
    cmd_exec('id')
  end

end ; end ; end ; end