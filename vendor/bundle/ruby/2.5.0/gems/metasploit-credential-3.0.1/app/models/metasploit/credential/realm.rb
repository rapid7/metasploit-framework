# The realm in which a {Metasploit::Credential::Public} can be used to authenticate or from which a
# {Metasploit::Credential::Private} was looted.
class Metasploit::Credential::Realm < ActiveRecord::Base
  extend ActiveSupport::Autoload

  include Metasploit::Model::Search

  autoload :Key

  #
  # Associations
  #

  # @!attribute cores
  #   The {Metasploit::Credential::Core core credentials} that combine this realm with
  #   {Metasploit::Credential::Private private credentials} and/or {Metasploit::Credential::Public public credentials}
  #   gathered from the realm or used to authenticated to the realm.
  #
  #   @return [ActiveRecord::Relation<Metasploit::Credential::Core>]
  has_many :cores,
           class_name: 'Metasploit::Credential::Core',
           dependent: :destroy,
           inverse_of: :realm

  #
  # Attributes
  #

  # @!attribute created_at
  #   When this realm was created.
  #
  #   @return [DateTime]

  # @!attribute key
  #   @note If a key is used more than once, it should be added to the {Metasploit::Credential::Realm::Key} constants
  #     and that constant should be used in place of the bare string.
  #
  #   The name of the key for the realm.
  #
  #   @return [String] An element of `Metasploit::Model::Realm::Key::ALL`

  # @!attribute updated_at
  #   The last time this realm was updated.
  #
  #   @return [DateTime]

  # @!attribute value
  #   The value of the {#key} for the realm.
  #
  #   @return [String]

  #
  # Search
  #

  search_attribute :key,
                   type: {
                       set: :string
                   }
  search_attribute :value,
                   type: :string

  #
  # Validations
  #

  validates :key,
            inclusion: {
                in: Metasploit::Model::Realm::Key::ALL
            },
            presence: true
  validates :value,
            presence: true,
            uniqueness: {
                scope: :key
            }

  #
  # Class Methods
  #

  # Set of valid values for searching {#key}.
  #
  # @return [Set<String>] `Metasploit::Model::Realm::Key::ALL` as a `Set`.
  # @see Metasploit::Model::Search::Operation::Set#membership
  # @see Metasploit::Model::Search::Operator::Attribute#attribute_set
  def self.key_set
    @key_set ||= Set.new Metasploit::Model::Realm::Key::ALL
  end

  #
  # Instance Methods
  #

  # @return [String]
  def to_s
    value.to_s
  end

  Metasploit::Concern.run(self)
end
