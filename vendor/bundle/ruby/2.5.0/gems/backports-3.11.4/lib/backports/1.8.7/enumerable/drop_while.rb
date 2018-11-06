unless Enumerable.method_defined? :drop_while
  require 'enumerator'

  module Enumerable
    # Standard in Ruby 1.8.7+. See official documentation[http://ruby-doc.org/core-1.9/classes/Enumerable.html]
    def drop_while
      return to_enum(:drop_while) unless block_given?
      ary = []
      dropping = true
      each do |obj|
        ary << obj unless dropping &&= yield(obj)
      end
      ary
    end
  end
end
