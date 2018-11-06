# Operation on an attribute that has a constrained Set of valid
# {Metasploit::Model::Search::Operation::Base#value values}.
class Metasploit::Model::Search::Operation::Set < Metasploit::Model::Search::Operation::Base
  extend ActiveSupport::Autoload

  autoload :Integer
  autoload :String

  #
  # Validations
  #

  validate :membership

  private

  # Validates that {#value} is a member of {Metasploit::Model::Search::Operation::Base#operator}
  # {Metasploit::Model::Search::Operator::Attribute#attribute_set}.
  #
  # @return [void]
  def membership
    if operator
      attribute_set = operator.attribute_set

      unless attribute_set.include? value
        # sort (because Sets are unordered) before inspecting so that lexigraphical sorting is NOT used
        sorted = attribute_set.sort
        # use inspect to differentiate between strings and integers or string and symbols
        inspected = sorted.map(&:inspect)

        # format as a human readable Set using { }
        comma_separated = inspected.join(', ')
        human_set = "{#{comma_separated}}"

        errors.add(:value, :inclusion, set: human_set)
      end
    end
  end
end