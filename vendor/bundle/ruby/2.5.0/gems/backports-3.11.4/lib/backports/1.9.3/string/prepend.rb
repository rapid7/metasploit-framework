unless String.method_defined? :prepend
  require 'backports/tools/arguments'

  class String
    def prepend(other_str)
      replace Backports.coerce_to_str(other_str) + self
      self
    end
  end
end
