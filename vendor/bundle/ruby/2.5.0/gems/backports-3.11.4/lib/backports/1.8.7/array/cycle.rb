unless Array.method_defined? :cycle
  require 'backports/tools/arguments'

  class Array
    def cycle(n = nil)
      return to_enum(:cycle, n) unless block_given?
      if n.nil?
        each{|e| yield e } until false
      else
        n = Backports.coerce_to_int(n)
        n.times{each{|e| yield e }}
      end
      nil
    end
  end
end
