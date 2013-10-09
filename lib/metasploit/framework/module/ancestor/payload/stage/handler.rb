# Module used by {Metasploit::Framework::Module::Ancestor::MetasploitModule#payload_metasploit_class} for stages to
# allow them to have handler_module in their `Class#ancestors` without having it on the stage module itself, which
# would cause the Metasploit::Model::Module::Ancestor#handler_type to be non-nil.
module Metasploit::Framework::Module::Ancestor::Payload::Stage::Handler
  extend Metasploit::Framework::Module::Ancestor::Handler
end