module Metasploit::Model::Association
  # Error raised by {Metasploit::Model::Association::ClassMethods#reflect_on_association!}.
  class Error < Metasploit::Model::Error
    #
    # Attributes
    #

    # @!attribute [r] model
    #   ActiveModel on which the association with {#name} was not found.
    #
    #   @return [Class]
    attr_reader :model

    # @!attribute [r] name
    #   Name of association that was not registered on {#model}.
    #
    #   @return [Symbol]
    attr_reader :name

    #
    # Methods
    #

    # @param attributes [Hash{Symbol => Object}]
    # @option attributes [Class] :model ActiveModel that is missing association with :name.
    # @option attributes [Symbol] :name name of the association that is missing.
    # @raise [KeyError] if :model is not given
    # @raise [KeyError] if :name is not given
    def initialize(attributes={})
      @model = attributes.fetch(:model)
      @name = attributes.fetch(:name)

      super("#{model} does not have #{name} association.")
    end
  end
end
