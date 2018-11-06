# An origin for {#cores core credentials} that were imported by a {#task} from a {#filename file}.
class Metasploit::Credential::Origin::Import < ActiveRecord::Base
  #
  # Associations
  #

  # @!attribute cores
  #   {Metasploit::Credential::Core Core credentials} imported from {#filename}.
  #
  #   @return [ActiveRecord::Relation<Metasploit::Credential::Core>]
  has_many :cores,
           as: :origin,
           class_name: 'Metasploit::Credential::Core',
           dependent: :destroy

  # @!attribute task
  #   The task that did the import.
  #
  #   @return [Mdm::Task]
  belongs_to :task,
             class_name: 'Mdm::Task',
             inverse_of: :import_credential_origins

  #
  # Attribute
  #

  # @!attribute created_at
  #   When the credentials were imported.
  #
  #   @return [DateTime]

  # @!attribute filename
  #   The `File.basename` of the file from which the {#cores core credentials} were imported.  Because only a
  #   basename is available, a {#filename} may be used more than once for the same {#task}.
  #
  #   @return [String]

  # @!attribute updated_at
  #   When this origin was last updated.
  #
  #   @return [DateTime]


  Metasploit::Concern.run(self)
end
