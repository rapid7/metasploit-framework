unless Enumerable.method_defined? :take_while
  require 'enumerator'

  module Enumerable
    # Standard in Ruby 1.8.7+. See official documentation[http://ruby-doc.org/core-1.9/classes/Enumerable.html]
    def take_while
      return to_enum(:take_while) unless block_given?
      inject([]) do |array, elem|
        return array unless yield elem
        array << elem
      end
    end
  end
end
