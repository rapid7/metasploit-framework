module Hike
  # `NormalizedArray` is an internal abstract wrapper class that calls
  # a callback `normalize_element` anytime an element is added to the
  # Array.
  #
  # `Extensions` and `Paths` are subclasses of `NormalizedArray`.
  class NormalizedArray < Array
    def initialize
      super()
    end

    def []=(*args)
      value = args.pop

      if value.respond_to?(:to_ary)
        value = normalize_elements(value)
      else
        value = normalize_element(value)
      end

      super(*args.concat([value]))
    end

    def <<(element)
      super normalize_element(element)
    end

    def collect!
      super do |element|
        result = yield element
        normalize_element(result)
      end
    end

    alias_method :map!, :collect!

    def insert(index, *elements)
      super index, *normalize_elements(elements)
    end

    def push(*elements)
      super(*normalize_elements(elements))
    end

    def replace(elements)
      super normalize_elements(elements)
    end

    def unshift(*elements)
      super(*normalize_elements(elements))
    end

    def normalize_elements(elements)
      elements.map do |element|
        normalize_element(element)
      end
    end
  end
end
