unless (Hash[[[:test, :test]]] rescue false)
  require 'backports/tools/arguments'

  class << Hash
    alias_method :constructor_without_key_value_pair_form, :[]
    def [](*args)
      if args.length == 1
        arg = args.first
        if (h = Backports.try_convert(arg, Hash, :to_hash))
          return allocate.replace(h)
        end
        if (kvps = Backports.is_array?(arg))
          h = {}
          kvps.each do |elem|
            next unless arr = Backports.is_array?(elem)
            next unless (1..2).include? arr.size
            h[arr.at(0)] = arr.at(1)
          end
          return h
        end
      end
      constructor_without_key_value_pair_form(*args)
    end
  end
end
