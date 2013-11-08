# Base class for class that sync the cache with metadata in a metasploit instance.
class Metasploit::Framework::Module::Instance::Synchronization::Base < Metasploit::Framework::Synchronization::Base
  include Metasploit::Framework::Module::Instance::Logging

  # Whether this synchronization class can synchronize the given `module_instance`.
  #
  # @return [false] Do not instantiation this class with `module_instance`.
  # @return [true] Instantiation this class with `module_instance`
  def self.can_synchronize?(module_instance)
    self::ALLOW_BY_ATTRIBUTE.all? { |attribute, support|
      module_instance.allows?(attribute) == support
    }
  end
end