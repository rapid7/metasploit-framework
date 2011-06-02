module RKelly
  module Visitable
    # Based off the visitor pattern from RubyGarden
    def accept(visitor, &block)
      klass = self.class.ancestors.find { |ancestor|
        visitor.respond_to?("visit_#{ancestor.name.split(/::/)[-1]}")
      }

      if klass
        visitor.send(:"visit_#{klass.name.split(/::/)[-1]}", self, &block)
      else
        raise "No visitor for '#{self.class}'"
      end
    end
  end
end
