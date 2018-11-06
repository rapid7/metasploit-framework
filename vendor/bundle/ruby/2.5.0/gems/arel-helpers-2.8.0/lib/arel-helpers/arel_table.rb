# encoding: UTF-8

module ArelHelpers
  module ArelTable

    extend ActiveSupport::Concern

    module ClassMethods

      if ActiveRecord.const_defined?(:Delegation)
        ActiveRecord::Delegation.delegate :[], to: :to_a
      end

      def [](name)
        arel_table[name]
      end

    end

  end
end
