unless ([[]].flatten(1) rescue false)
  require 'backports/tools/alias_method_chain'
  require 'backports/tools/arguments'

  class Array
    # Recursively flatten any contained Arrays into an one-dimensional result.
    # Adapted from rubinius'
    def flatten_with_optional_argument(level=-1)
      dup.flatten!(level) || self
    end

    # Flattens self in place as #flatten. If no changes are
    # made, returns nil, otherwise self.
    # Adapted from rubinius'
    def flatten_with_optional_argument!(level=-1)
      level = Backports.coerce_to_int(level)
      return flatten_without_optional_argument! if level < 0

      out = []
      ret = recursively_flatten_finite(self, out, level)
      replace(out) if ret
      ret
    end

    Backports.alias_method_chain self, :flatten, :optional_argument
    Backports.alias_method_chain self, :flatten!, :optional_argument

    # Helper to recurse through flattening
    # Adapted from rubinius'; recursion guards are not needed because level is finite
    def recursively_flatten_finite(array, out, level)
      ret = nil
      if level <= 0
        out.concat(array)
      else
        array.each do |o|
          if ary = Backports.is_array?(o)
            recursively_flatten_finite(ary, out, level - 1)
            ret = self
          else
            out << o
          end
        end
      end
      ret
    end
    private :recursively_flatten_finite
  end
end
