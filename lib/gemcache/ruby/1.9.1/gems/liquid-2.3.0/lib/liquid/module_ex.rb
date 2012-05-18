# Copyright 2007 by Domizio Demichelis
# This library is free software. It may be used, redistributed and/or modified
# under the same terms as Ruby itself
#
# This extension is usesd in order to expose the object of the implementing class
# to liquid as it were a Drop. It also limits the liquid-callable methods of the instance
# to the allowed method passed with the liquid_methods call
# Example:
#
# class SomeClass
#   liquid_methods :an_allowed_method
#
#   def an_allowed_method
#     'this comes from an allowed method'
#   end
#   def unallowed_method
#     'this will never be an output'
#   end
# end
#
# if you want to extend the drop to other methods you can defines more methods
# in the class <YourClass>::LiquidDropClass
#
#   class SomeClass::LiquidDropClass
#     def another_allowed_method
#       'and this from another allowed method'
#     end
#   end
# end
#
# usage:
# @something = SomeClass.new
#
# template:
# {{something.an_allowed_method}}{{something.unallowed_method}} {{something.another_allowed_method}}
#
# output:
# 'this comes from an allowed method and this from another allowed method'
#
# You can also chain associations, by adding the liquid_method call in the
# association models.
#
class Module

  def liquid_methods(*allowed_methods)
    drop_class = eval "class #{self.to_s}::LiquidDropClass < Liquid::Drop; self; end"
    define_method :to_liquid do
      drop_class.new(self)
    end
    drop_class.class_eval do
      def initialize(object)
        @object = object
      end
      allowed_methods.each do |sym|
        define_method sym do
          @object.send sym
        end
      end
    end
  end

end
