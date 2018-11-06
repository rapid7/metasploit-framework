# frozen_string_literal: true

# Backward compatibility for gem specification lookup
# @see Gem::SourceIndex
module YARD
  module GemIndex
    module_function

    def find_all_by_name(*args)
      if defined?(Gem::Specification) && Gem::Specification.respond_to?(:find_all_by_name)
        Gem::Specification.find_all_by_name(*args)
      else
        Gem.source_index.find_name(*args)
      end
    end

    def each(&block)
      if defined?(Gem::Specification) && Gem::Specification.respond_to?(:each)
        Gem::Specification.each(&block)
      else
        Gem.source_index.find_name('').each(&block)
      end
    end

    def all
      each.to_a
    end
  end
end
