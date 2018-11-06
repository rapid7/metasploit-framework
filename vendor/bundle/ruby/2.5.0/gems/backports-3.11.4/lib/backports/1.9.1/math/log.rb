unless (Math.log(2, 2) rescue false)
  require 'backports/tools/alias_method_chain'
  require 'backports/tools/arguments'

  class << Math
    # Standard in Ruby 1.9. See official documentation[http://ruby-doc.org/core-1.9/classes/Math.html]
    def log_with_optional_base(numeric, base = Backports::Undefined)
      if base.equal?(Backports::Undefined)
        # Math.log(n) in 1.9.1 no longer accepts string arguments as it
        # did on 1.8.x, but we won't risk redefining existing behavior
        # when called with just one argument.
        log_without_optional_base(numeric)
      else
        # Math.log(n, b) in 1.9.1 does not accept string arguments:
        raise TypeError, "can't convert String into Float" if numeric.is_a?(String) || base.is_a?(String)
        log_without_optional_base(numeric) / log_without_optional_base(base)
      end
    end
    Backports.alias_method_chain self, :log, :optional_base
  end
end
