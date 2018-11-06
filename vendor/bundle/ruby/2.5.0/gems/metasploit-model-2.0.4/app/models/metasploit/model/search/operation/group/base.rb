# A group of one or more {#children child operations} from an operator's `#operate_on`, should be visited the same as
# {Metasploit::Model::Search::Group::Base}.
class Metasploit::Model::Search::Operation::Group::Base < Metasploit::Model::Search::Operation::Base
  #
  # Attributes
  #

  # @!attribute [rw] children
  #   Children operations of union.
  #
  #   @return [Array<Metasploit::Model::Search::Operation::Base>]
  attr_writer :children

  #
  #
  # Validations
  #
  #

  #
  # Method Validations
  #

  # validate_associated is defined by ActiveRecord, so have to do it manually here.
  validate :children_valid

  #
  # Attribute Validations
  #

  validates :children,
            :length => {
                :minimum => 1
            }

  #
  # Methods
  #

  def children
    @children ||= []
  end

  private

  # Validates that {#children} are valid
  #
  # @return [void]
  def children_valid
    if children.is_a? Enumerable
      # can't use children.all?(&:valid?) as it will short-circuit and want all children to have validation errors
      valids = children.map(&:valid?)

      unless valids.all?
        errors.add(:children, :invalid, value: children)
      end
    end
  end
end