# -*- coding: binary -*-

require 'msf/core'
require 'rex/text'
require 'rex/exploitation/jsobfu'

module Rex
module Exploitation
module Js


class Detect

  #
  # Provides several javascript functions for determining the OS and browser versions of a client.
  #
  # getVersion():  returns an object with the following properties
  # os_name      -  OS name, one of the Msf::OperatingSystems constants
  # os_flavor    -  OS flavor as a string (e.g.: "XP", "2000")
  # os_sp        -  OS service pack (e.g.: "SP2", will be empty on non-Windows)
  # os_lang      -  OS language (e.g.: "en-us")
  # ua_name      -  Client name, one of the Msf::HttpClients constants
  # ua_version   -  Client version as a string (e.g.: "3.5.1", "6.0;SP2")
  # arch         -  Architecture, one of the ARCH_* constants
  #
  # The following functions work on the version returned in obj.ua_version
  #
  # ua_ver_cmp(a, b): returns -1, 0, or 1 based on whether a < b, a == b, or a > b respectively
  # ua_ver_lt(a, b):  returns true if a < b
  # ua_ver_gt(a, b):  returns true if a > b
  # ua_ver_eq(a, b):  returns true if a == b
  #
  def self.os(custom_js = '')
    js  = custom_js
    js << ::File.read(::File.join(Msf::Config.data_directory, "js", "detect", "os.js"))

    Rex::Exploitation::JSObfu.new(js)
  end


  #
  # Provides javascript functions to determine IE addon information.
  #
  # getMsOfficeVersion(): Returns the version for Microsoft Office
  #
  def self.ie_addons(custom_js = '')
    js  = custom_js
    js << ::File.read(::File.join(Msf::Config.data_directory, "js", "detect", "ie_addons.js"))

    Rex::Exploitation::JSObfu.new(js)
  end

  #
  # Provides javascript functions that work for all browsers to determine addon information
  #
  # getJavaVersion(): Returns the Java version
  # hasSilverlight(): Returns whether Silverlight is enabled or not
  #
  def self.misc_addons(custom_js = '')
    js  = custom_js
    js << ::File.read(::File.join(Msf::Config.data_directory, "js", "detect", "misc_addons.js"))

    Rex::Exploitation::JSObfu.new(js)
  end

end
end
end
end
