# Synchronizes {#metasploit_instance metasploit instance's}
# {Msf::Module#platform} {Msf::Module::PlatformList#platforms} to
# {#module_instance} `Metasploit::Model::Module::Instance#module_platforms`.
class Metasploit::Framework::Module::Instance::Synchronization::ModulePlatforms < Metasploit::Framework::Module::Instance::Synchronization::Base
  include Metasploit::Framework::Scoped::Synchronization::Platform

  #
  # CONSTANTS
  #

  # if module instance supports targets then platforms will be derived from targets and platforms will be cached in
  # {#cache_targets}.
  ALLOW_BY_ATTRIBUTE = {
      module_platforms: true,
      targets: false
  }

  #
  # Methods
  #

  def source_attributes_set
    unless instance_variable_defined? :@source_attributes_set
      # if there are targets then use the union of their platforms
      if destination.allows?(:targets)
        @source_attributes_set = destination.targets.each_with_object(Set.new) { |module_target, set|
          module_target.target_platforms.each do |target_platform|
            set.add target_platform.platform.fully_qualified_name
          end
        }
      else
        @source_attribuets_set = super
      end
    end

    @source_attributes_set
  end
end
