require 'factory_bot/declaration/static'
require 'factory_bot/declaration/dynamic'
require 'factory_bot/declaration/association'
require 'factory_bot/declaration/implicit'

module FactoryBot
  # @api private
  class Declaration
    attr_reader :name

    def initialize(name, ignored = false)
      @name    = name
      @ignored = ignored
    end

    def to_attributes
      build
    end

    protected
    attr_reader :ignored
  end
end
