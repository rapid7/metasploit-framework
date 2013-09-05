# Error raised by {Msf::Modules::Namespace#metasploit_class!} if it cannot the namespace_module does not have a constant
# with {Msf::Framework::Major} or lower as a number after 'Metasploit', which indicates a compatible Msf::Module.
class Metasploit::Framework::Module::Ancestor::Error::MetasploitModuleIncompatibility < Metasploit::Framework::Module::Ancestor::Error::Base
  def initialize(attributes={})
    super_attributes = {
        :causal_message => 'Missing compatible Metasploit<major_version> class constant',
    }.merge(attributes)

    super(super_attributes)
  end
end