# Macro of {#actions} to run at once.
class Mdm::Macro < ActiveRecord::Base
  extend MetasploitDataModels::SerializedPrefs

  #
  # Attributes
  #

  # @!attribute created_at
  #   When this macro was created.
  #
  #   @return [DateTime]

  # @!attribute description
  #   Long description of what the macro does.
  #
  #   @return [String]

  # @!attribute  name
  #   The name of this macro.
  #
  #   @return [String]

  # @!attribute owner
  #   {Mdm::User#username Name of user} that owns this macro.
  #
  #   @return [String]

  # @!attribute updated_at
  #   When this macro was last updated.
  #
  #   @return [DateTime]

  #
  # Serialization
  #

  # Actions run by this macro.
  #
  # @return [Array<Hash{Symbol=>Object}>] Array of action hashes.  Each action hash is have key :module with value
  #   of an {Mdm::Module::Detail#fullname} and and key :options with value of options used to the run the module.
  serialize :actions, MetasploitDataModels::Base64Serializer.new

  # Preference for this macro, shared across all actions.
  #
  # @return [Hash]
  serialize :prefs, MetasploitDataModels::Base64Serializer.new

  # The maximum number of seconds that this macro is allowed to run.
  #
  # @return [Integer]
  serialized_prefs_attr_accessor :max_time

  #
  # Validations
  #

  validates :name, :presence => true, :format => /\A[^'|"]+\z/

  Metasploit::Concern.run(self)
end

