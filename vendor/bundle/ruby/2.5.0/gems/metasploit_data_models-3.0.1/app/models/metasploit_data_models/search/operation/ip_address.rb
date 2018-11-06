# Searches an `inet` column in a PostgreSQL database using
# {MetasploitDataModels::IPAddress::V4::Single a standard IPv4 address},
# {MetasploitDataModels::IPAddress::V4::CIDR an IPv4 CIDR block}, or
# {MetasploitDataModels::IPAddress::V4::Range an IPv4 address range}.
class MetasploitDataModels::Search::Operation::IPAddress < Metasploit::Model::Search::Operation::Base
  include MetasploitDataModels::Match::Parent

  #
  # Match Children
  #

  # in order of precedence, so simpler single IPv4 addresses are matched before the more complex ranges which may
  # degenerate to equivalent formatted value
  match_children_named %w{
    MetasploitDataModels::IPAddress::V4::Single
    MetasploitDataModels::IPAddress::V4::CIDR
    MetasploitDataModels::IPAddress::V4::Range
  }

  #
  #
  # Validations
  #
  #

  #
  # Validation Methods
  #

  validate :value_valid

  #
  # Attribute Validations
  #

  validates :value,
            presence: true

  #
  # Instance Method
  #

  # @param formatted_value [#to_s]
  def value=(formatted_value)
    @value = match_child(formatted_value) || formatted_value
  end

  private

  # Validates that `#value` is valid.
  #
  # @return [void]
  def value_valid
    if value.present?
      unless value.respond_to?(:valid?) && value.valid?
        errors.add(:value, :invalid)
      end
    end
  end
end