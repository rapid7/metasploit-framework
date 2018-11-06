# Joins a {Mdm::Module::Detail} and {Mdm::Ref} indirectly through the {Mdm::Module::Detail#refname} matching {#module},
# {Mdm::Module::Detail#mtype} matching {#mtype}, and {Mdm::Ref#name} matching {#ref}.
class Mdm::ModRef < ActiveRecord::Base
  #
  # Attributes
  #

  # @!attribute module
  #   An {Mdm::Module::Detail#refname}.
  #
  #   @return [String]

  # @!attribute mtype
  #   An {Mdm::Module::Detail#mtype}.
  #
  #   @return [String]

  # @!attribute ref
  #   An {Mdm::Ref#name}.
  #
  #   @return [String]

  Metasploit::Concern.run(self)
end
