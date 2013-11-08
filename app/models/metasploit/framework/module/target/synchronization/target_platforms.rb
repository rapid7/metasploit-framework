# Synchronizes {#source Msf::Module::Target} {Msf::Module::Target#platform platforms} to {#destination module target}
# platforms (`Metasploit::Model::Module::Target#target_platforms`).
class Metasploit::Framework::Module::Target::Synchronization::TargetPlatforms < Metasploit::Framework::Synchronization::Base
  include Metasploit::Framework::Scoped::Synchronization::Platform
end