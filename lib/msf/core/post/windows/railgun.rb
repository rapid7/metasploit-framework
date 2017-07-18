# -*- coding: binary -*-
require 'rex/post/meterpreter/extensions/stdapi/railgun/railgun'

module Msf
class Post
module Windows
module Railgun

  # Go through each dll and add a corresponding convenience method of the same name
  Rex::Post::Meterpreter::Extensions::Stdapi::Railgun::Railgun::BUILTIN_LIBRARIES['windows'].each do |api|
    # We will be interpolating within an eval. We exercise due paranoia.
    unless api.to_s =~ /^\w+$/
      print_error 'Something is seriously wrong with Railgun.BUILTIN_LIBRARIES list'
      next
    end

    # don't override existing methods
    if method_defined? api.to_sym
      # We don't warn as the override may have been intentional
      next
    end

    # evaling a String is faster than calling define_method
    eval "def #{api.to_s}; railgun.#{api.to_s}; end"
  end

  #
  # Return an array of windows constants names matching +winconst+
  #
  def select_const_names(winconst, filter_regex=nil)
    railgun.constant_manager.select_const_names(winconst, filter_regex)
  end

  #
  # Returns an array of windows error code names for a given windows error code matching +err_code+
  #
  def lookup_error (err_code, filter_regex=nil)
    select_const_names(err_code, /^ERROR_/).select do |name|
      name =~ filter_regex
    end
  end

  #
  # Read +length+ bytes starting at +address+
  #
  def memread(address, length)
    railgun.memread(address, length)
  end

  #
  # Write +length+ bytes starting at +address+
  #
  def memwrite(address, length)
    railgun.memwrite(address, length)
  end

  def railgun
    client.railgun
  end

  #
  # Returns the pointer size of the remote system
  #
  def pointer_size
    railgun.util.pointer_size
  end
end
end
end
end
