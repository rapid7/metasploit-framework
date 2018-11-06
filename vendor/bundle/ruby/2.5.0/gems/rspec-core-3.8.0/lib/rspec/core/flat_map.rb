module RSpec
  module Core
    # @private
    module FlatMap
      if [].respond_to?(:flat_map)
        def flat_map(array, &block)
          array.flat_map(&block)
        end
      else # for 1.8.7
        # :nocov:
        def flat_map(array, &block)
          array.map(&block).flatten(1)
        end
        # :nocov:
      end

      module_function :flat_map
    end
  end
end
