# Synchronizes {#source Msf::Module::Target} {Msf::Module::Target#arch architectures} to {#destination module target}
# architectures (`Metasploit::Model::Module::Target#target_architectures`).
class Metasploit::Framework::Module::Target::Synchronization::TargetArchitectures < Metasploit::Framework::Synchronization::Base
  include Metasploit::Framework::Scoped::Synchronization::Architecture
end