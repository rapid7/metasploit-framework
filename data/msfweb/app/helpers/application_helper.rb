# Copyright (c) 2006 L.M.H <lmh@info-pull.com>
# All Rights Reserved.

# Methods added to this helper will be available to all templates in the application.
module ApplicationHelper

  # Returns a hash with ruby version, platform and Metasploit version.
  def return_env_info()
    ret = {}
    ret[:platform] = RUBY_PLATFORM
    ret[:rubyver]  = RUBY_VERSION
    ret[:msfver]   = Msf::Framework::Version
    return ret
  end
  
end
