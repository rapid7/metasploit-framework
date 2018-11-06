unless Enumerable.method_defined? :each_entry
  module Enumerable
    def each_entry(*pass)
      return to_enum(:each_entry, *pass) unless block_given?
      each(*pass) do |*args|
        yield args.size == 1 ? args[0] : args
      end
      self
    end
  end
end
