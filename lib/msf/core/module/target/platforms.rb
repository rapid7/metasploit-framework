module Msf::Module::Target::Platforms
  # @deprecated use {#platform_list} instead.
  # @return (see #platform_list)
  def platform
    ActiveSupport::Deprecation.warn "#{self}##{__method__} is deprecated.  Use #{self.class}#platform_list instead"
    platform_list
  end

  # The platform list declared for this target in the info hash.  For the actual platform supported by this target
  # (i.e when it has no declared platform and defers to the module's platforms), use {#platform_list}.
  #
  # @return [nil] if 'Platform' not in target {Msf::Module::Target#opts}.
  # @return [Msf::Module::PlatformList] if 'Platform' declared for target.
  def declared_platform_list
    unless instance_variable_defined? :@declared_platform_list
      raw_platforms = opts['Platform']

      if raw_platforms
        @declared_platform_list = Msf::Module::PlatformList.transform(
            raw_platforms,
            module_class_full_names: [
                metasploit_instance.class.module_class.full_name
            ]
        )
      else
        # nil to signal to defer to metasploit_instance in {#platform_list}
        @declared_platform_list = nil
      end
    end

    @declared_platform_list
  end

  # The platforms that this target supports.  Either the {#declared_platform_list} or the
  # {Msf::Module::Platforms#platform_list} from {Msf::Module::Target#metasploit_instance}.
  #
  # @return [Msf::Module::PlatformList]
  def platform_list
    declared_platform_list || metasploit_instance.platform_list
  end
end