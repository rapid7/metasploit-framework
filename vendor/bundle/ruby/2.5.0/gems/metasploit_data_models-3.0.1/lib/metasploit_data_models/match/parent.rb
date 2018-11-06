# Uses classes that extend {MetasploitDataModels::Match::Child}
#
# @example Add match_child to class.
#   class Parent
#     include MetasploitDataModels::Match::Parent
#
#     match_children_named %w{FirstChild SecondChild}
#   end
module MetasploitDataModels::Match::Parent
  extend ActiveSupport::Concern

  # @example Declaring children classes
  #   class FirstChild < Metasploit::Model::Base
  #     extend MetasploitDataModels::Match::Child
  #
  #     #
  #     # CONSTANTS
  #     #
  #
  #     # Matches a range.
  #     MATCH_REGEXP = /\A\d+-\d+\z/
  #
  #     #
  #     # Attributes
  #     #
  #
  #     # @!attribute value
  #     #   The range
  #     #
  #     attr_accessor :value
  #   end
  #
  #   class SecondChild < Metasploit::Model::Base
  #     extend MetasploitDataModels::Match::Child
  #
  #     #
  #     # CONSTANTS
  #     #
  #
  #     # Matches a range.
  #     MATCH_REGEXP = /\A\d+\z/
  #
  #     #
  #     # Attributes
  #     #
  #
  #     # @!attribute value
  #     #   The range
  #     #
  #     attr_accessor :value
  #   end
  #
  #   class Parent
  #     include MetasploitDataModels::Match::Parent
  #
  #     match_children_named %w{FirstChild SecondChild}
  #   end
  module ClassMethods
    # `Class#name` for classes that extend {MetasploitDataModels::Match::Child} and should be tested using `match`.
    #
    # @return [Array<String>]
    def match_child_names
      @match_child_names ||= []
    end

    # `Class`es on which to call `match` in {MetasploitDataModels::Match::Parent#match_child}
    #
    # @return [Array<String>]
    def match_children
      @match_children ||= match_child_names.map(&:constantize)
    end

    # @note `Class`es named `class_names`
    # Register the given `class_names` as `Class#name`s for children classes for
    # {MetasploitDataModels::Match::Parent#match_child}.
    #
    # @return [Array<String>] class_names`
    def match_children_named(class_names)
      @match_child_names = class_names
    end
  end

  #
  # Instance Methods
  #

  # @param formatted_value [#to_s] A formatted value for the child's `#value`.
  # @return [Object] instance of the first of {ClassMethods#match_children} that matches the `formatted_value`.
  # @return [nil] if no {ClassMethods#match_children} matches the `formatted_value`.
  def match_child(formatted_value)
    child = nil

    self.class.match_children.each do |child_class|
      child = child_class.match(formatted_value)

      if child
        break
      end
    end

    child
  end
end
