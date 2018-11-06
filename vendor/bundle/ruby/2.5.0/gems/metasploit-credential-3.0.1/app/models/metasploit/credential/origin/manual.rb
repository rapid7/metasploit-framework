# Origin of {#cores core credentials} that are manually entered by a {#user}.
class Metasploit::Credential::Origin::Manual < ActiveRecord::Base
  #
  # Associations
  #

  # @!attribute cores
  #   {Metasploit::Credential::Core Core credentials} that were entered by the {#user}.
  #
  #   @return [ActiveRecord::Relation<Metasploit::Credential::Core>]
  has_many :cores,
           as: :origin,
           class_name: 'Metasploit::Credential::Core',
           dependent: :destroy

  # @!attribute user
  #   The user that manually enters the credentials.
  #
  #   @return [Mdm::User]
  belongs_to :user,
             class_name: 'Mdm::User',
             inverse_of: :credential_origins

  #
  # Attribute
  #

  # @!attribute created_at
  #   When the credentials were manually created.
  #
  #   @return [DateTime]

  # @!attribute updated_at
  #   When this origin was last updated.
  #
  #   @return [DateTime]

  #
  # Validations
  #

  validates :user,
            presence: true

  Metasploit::Concern.run(self)
end
