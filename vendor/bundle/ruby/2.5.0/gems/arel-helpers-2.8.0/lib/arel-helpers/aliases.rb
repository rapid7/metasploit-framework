# encoding: UTF-8

module ArelHelpers

  module Aliases
    extend ActiveSupport::Concern

    module ClassMethods
      def aliased_as(*args)
        aliases = args.map { |name| arel_table.alias(name) }

        if block_given?
          yield *aliases
        else
          aliases
        end
      end
    end
  end

end
