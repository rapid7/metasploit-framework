# encoding: UTF-8

require 'forwardable'
require 'enumerator'

module ArelHelpers
  class QueryBuilder
    extend Forwardable
    include Enumerable

    attr_reader :query
    def_delegators :@query, :to_a, :to_sql, :each

    TERMINAL_METHODS = [:count, :first, :last]
    TERMINAL_METHODS << :pluck if ActiveRecord::VERSION::MAJOR >= 4

    def_delegators :@query, *TERMINAL_METHODS

    def initialize(query)
      @query = query
    end

    protected

    def reflect(query)
      dup.tap { |obj| obj.instance_variable_set('@query'.freeze, query) }
    end
  end
end
