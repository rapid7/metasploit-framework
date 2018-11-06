module FactoryBot
  # @api private
  class DeclarationList
    include Enumerable

    def initialize(name = nil)
      @declarations = []
      @name         = name
      @overridable  = false
    end

    def declare_attribute(declaration)
      delete_declaration(declaration) if overridable?

      @declarations << declaration
      declaration
    end

    def overridable
      @overridable = true
    end

    def attributes
      @attributes ||= AttributeList.new(@name).tap do |list|
        to_attributes.each do |attribute|
          list.define_attribute(attribute)
        end
      end
    end

    def each(&block)
      @declarations.each(&block)
    end

    private

    def delete_declaration(declaration)
      @declarations.delete_if { |decl| decl.name == declaration.name }
    end

    def to_attributes
      @declarations.inject([]) { |result, declaration| result += declaration.to_attributes }
    end

    def overridable?
      @overridable
    end
  end
end
