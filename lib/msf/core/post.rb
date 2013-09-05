# -*- coding: binary -*-

require 'msf/core/post_mixin'

module Msf

#
# A Post-exploitation module
#
#
class Post < Msf::Module
  include PostMixin

  def setup; end

  def type
    MODULE_POST
  end

  def self.type
    MODULE_POST
  end

  #
  # Create an anonymous module not tied to a file.  Only useful for IRB.
  #
  def self.create(session)
    mod = new
    mod.instance_variable_set(:@session, session)
    # Have to override inspect because for whatever reason, +type+ is coming
    # from the wrong scope and i can't figure out how to fix it.
    mod.instance_eval do
      def inspect
        "#<Msf::Post anonymous>"
      end
    end
    mod.class.refname = "anonymous"

    mod
  end
end

end

