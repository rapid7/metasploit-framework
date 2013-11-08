# Synchronizes {#metasploit_instance metasploit instance's}
# {Msf::Module#stance} to
# {#module_instance} `Metasploit::Model::Module::Instance#stance`.
class Metasploit::Framework::Module::Instance::Synchronization::Stance < Metasploit::Framework::Module::Instance::Synchronization::Base
  #
  # Synchronization
  #

  synchronize do
    rescue_module_instance_error(destination, NoMethodError) {
      destination.stance = source.stance
    }
  end

  #
  # Methods
  #

  def self.can_synchronize?(module_instance)
    module_instance.stanced?
  end
end