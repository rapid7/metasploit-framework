# Synchronizes {#metasploit_instance metasploit instance's}
# {Msf::Module#architecture_abbreviations architecture abbreviations} to
# {#module_instance} `Metasploit::Model::Module::Instance#module_architectures`.
class Metasploit::Framework::Module::Instance::Synchronization::ModuleArchitectures < Metasploit::Framework::Module::Instance::Synchronization::Base
  include Metasploit::Framework::Scoped::Synchronization::Architecture
  #
  # CONSTANTS
  #

  # if module instance supports targets then architectures will be derived from targets and architectures will be cached
  # in {#cache_targets}.
  ALLOW_BY_ATTRIBUTE = {
      module_architectures: true,
      targets: false
  }

  def source_attributes_set
    unless instance_variable_defined? :@source_attributes_set
      # if there are targets then use the union of their architectures
      if destination.allows?(:targets)
        @source_attributes_set = destination.targets.each_with_object(Set.new) { |module_target, set|
          module_target.target_architectures.each do |target_architecture|
            set.add target_architecture.architecture.abbreviation
          end
        }
      else
        @source_attributes_set = super
      end
    end

    @source_attributes_set
  end
end
