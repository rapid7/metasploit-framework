require 'msf/core/module/platform_list'

# Methods dealing with platform_list supported by this module.  Not to be confused with {Msf::Module::Platform}, which is a
# single platform and {Msf::Module::PlatformList}, which is a collection of {Msf::Module::Platform}.
module Msf::Module::Platforms
  # @deprecated Use {#platform_list} instead.
  # @return (see #platform_list)
  def platform
    ActiveSupport::Deprecation.warn "#{self}##{__method__} is deprecated.  Use #{self}#platform_list instead"
    platform_list
  end

  # @deprecated Use {#platform_list_to_s} instead.
  # @return (see #platform_list_to_s)
  def platform_to_s
    ActiveSupport::Deprecation.warn "#{self}##{__method__} is deprecated.  Use #{self}#platform_list_to_s instead"
    platform_list_to_s
  end

  # List of supported platform_list.
  #
  # @return [Msf::Module::PlatformList]
  def platform_list
    @platform_list ||= Msf::Module::PlatformList.transform(module_info['Platform'])
  end

  # Sets the supported platform_list for this module.
  #
  # @param platform_list [Msf::Module::PlatformList, Array<String>, String] one or more platform_list that this module should
  #   support.
  # @return [Msf::Module::PlatformList]
  def platform_list=(platform_list)
    if platform_list.is_a? Msf::Module::PlatformList
      @platform_list = platform_list
    else
      @platform_list = Msf::Module::PlatformList.transform(platform_list)
    end
  end

  # Comma separated list of supported platforms.
  #
  # @return [String]
  def platform_list_to_string
    if platform_list.all?
      'All'
    else
      platform_list.names.join(', ')
    end
  end
end