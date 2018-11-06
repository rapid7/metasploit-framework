# Base `Class` for all private credentials.   A private credential is any credential that should not be publicly
# disclosed, such as a {Metasploit::Credential::Password password}, password hash, or key file.
#
# Uses Single Table Inheritance to store subclass name in {#type} per Rails convention.
class Metasploit::Credential::Private < ActiveRecord::Base
  include Metasploit::Model::Search

  #
  # Associations
  #

  # @!attribute cores
  #   The {Metasploit::Credential::Core core credentials} that combine this private credential with its
  #   {Metasploit::Credential::Public public credential} and/or {Metasploit::Credential::Realm realm}.
  #
  #   @return [ActiveRecord::Relation<Metasploit::Credential::Core>]
  has_many :cores,
           class_name: 'Metasploit::Credential::Core',
           dependent: :destroy,
           inverse_of: :private

  #
  # Attributes
  #

  # @!attribute created_at
  #   When this private credential was created.
  #
  #   @return [DateTime]

  # @!attribute data
  #   The private data for this credential.  The semantic meaning of this data varies based on subclass.
  #
  #   @return [String]

  # @!attribute id
  #   The id of this private credential in the database.  {#id} sequence is shared across all subclass {#type}s, so
  #   {#id} alone acts as a primary key without the need for a compound primary key (id, type).
  #
  #   @return [Integer] if saved to database.
  #   @return [nil] if not saved to database.

  # @!attribute type
  #   The name of the `Class`.  Used to instantiate the correct subclass when retrieving records from the database.
  #
  #   @return [String]

  # @!attribute updated_at
  #   The last time this private credential was updated.
  #
  #   @return [DateTime]

  #
  #
  # Search
  #
  #

  #
  # Search Attributes
  #

  search_attribute :data,
                   type: :string

  #
  # Search Withs
  #

  search_with Metasploit::Credential::Search::Operator::Type,
              class_names: %w{
                Metasploit::Credential::NonreplayableHash
                Metasploit::Credential::NTLMHash
                Metasploit::Credential::Password
                Metasploit::Credential::SSHKey
              }

  #
  # Validations
  #

  validates :data,
            non_nil: true,
            uniqueness: {
                scope: :type
            }

  #
  # Instance Methods
  #

  # A string suitable for displaying to the user
  #
  # @return [String]
  def to_s
    data.to_s
  end

  Metasploit::Concern.run(self)
end
