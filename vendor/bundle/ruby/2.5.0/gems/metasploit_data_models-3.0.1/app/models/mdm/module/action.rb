# Actions that auxiliary or post Metasploit Modules can perform.  Actions are used to select subcommand-like behavior
# implemented by the same Metasploit Nodule.  The semantics of a given action are specific to a given
# {Mdm::Module::Detail Metasploit Module}: if two {Mdm::Module::Detail Metasploit Modules} have
# {Mdm::Module::Action actions} with the same {Mdm::Module::Action#name name}, no similarity should be assumed between
# those two {Mdm::Module::Action actions} or {Mdm::Module::Detail Metasploit Modules}.
class Mdm::Module::Action < ActiveRecord::Base
  self.table_name = 'module_actions'  

  #
  # Associations
  #

  # The Metasploit Module with this action.
  belongs_to :detail, :class_name => 'Mdm::Module::Detail'

  #
  # Attributes
  #

  # @!attribute [rw] name
  #   The name of this action.
  #
  #   @return [String]

  #
  # Validations
  #

  validates :detail, :presence => true
  validates :name, :presence => true

  Metasploit::Concern.run(self)
end
