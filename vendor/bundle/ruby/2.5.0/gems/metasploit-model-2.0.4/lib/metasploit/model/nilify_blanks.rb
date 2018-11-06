# Registers before validation callback to convert the given attributes to `nil` if they are blank.  This can be used
# to normalize empty attributes to NULL in the database so queries don't have to handle both `= ''` and `IS NULL`.
module Metasploit::Model::NilifyBlanks
  extend ActiveSupport::Concern

  included do
    include ActiveModel::Validations
    include ActiveModel::Validations::Callbacks

    before_validation :nilify_blanks
  end

  # Adds DSL methods once NilifyBlanks is included so that attributes where blanks should be changed to `nil` can be
  # declared.
  module ClassMethods
    # Declares that `attributes` should be changed to `nil` before validation if they are blank.
    #
    # @param attributes [Enumerable<Symbol>] one or more attribute names
    # @return [void]
    def nilify_blank(*attributes)
      nilify_blank_attribute_set.merge(attributes)
    end

    # Set of all attributes registered with {#nilify_blank}.
    #
    # @return [Set<Symbol>]
    def nilify_blank_attribute_set
      @nilify_blank_attribute_set ||= Set.new
    end
  end

  #
  # Instance Methods
  #

  # Before validation callback to change any attributes in {ClassMethods#nilify_blank_attribute_set} that are blank to
  # `nil`.
  #
  # @return [void]
  def nilify_blanks
    self.class.nilify_blank_attribute_set.each do |attribute|
      value = send(attribute)

      if value.respond_to? :blank? and value.blank?
        send("#{attribute}=", nil)
      end
    end
  end
end
