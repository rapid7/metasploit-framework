class Pry
  module Forwardable
    require 'forwardable'
    include ::Forwardable

    #
    # Since Ruby 2.4, Forwardable will print a warning when
    # calling a method that is private on a delegate, and
    # in the future it could be an error: https://bugs.ruby-lang.org/issues/12782#note-3
    #
    # That's why we revert to a custom implementation for delegating one
    # private method to another.
    #
    def def_private_delegators(target, *private_delegates)
      private_delegates.each do |private_delegate|
        define_method(private_delegate) do |*a, &b|
          instance_variable_get(target).__send__(private_delegate, *a, &b)
        end
      end
      class_eval { private(*private_delegates) }
    end
  end
end
