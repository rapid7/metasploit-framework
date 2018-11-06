# A search operator declared with
# {Metasploit::Model::Search::Attribute::ClassMethods#search_attribute search_attribute}.
class Metasploit::Model::Search::Operator::Attribute < Metasploit::Model::Search::Operator::Single
  #
  # CONSTANTS
  #

  # The valid {#type types}.
  TYPES = [
      :boolean,
      :date,
      :integer,
      {
          set: :integer
      },
      {
          set: :string
      },
      :string
  ]

  #
  # Attributes
  #

  # @!attribute [r] attribute
  #   The attribute on {Metasploit::Model::Search::Operator::Base#klass klass} that is searchable.
  #
  #   @return [Symbol] the attribute name
  attr_accessor :attribute

  # @!attribute [r] type
  #   The type of {#attribute}.
  #
  #   @return [Symbol] Value from {TYPES}.
  attr_accessor :type

  #
  # Validations
  #

  validates :attribute, :presence => true
  validates :type,
            :inclusion => {
                :in => TYPES
            }

  #
  # Methods
  #

  # Set for {#attribute} as provided by {Metasploit::Model::Search::Operator::Base#klass #klass}.
  #
  # @return [Enumerable, #include?]
  def attribute_set
    klass.send("#{attribute}_set")
  end

  alias_method :name, :attribute
end
