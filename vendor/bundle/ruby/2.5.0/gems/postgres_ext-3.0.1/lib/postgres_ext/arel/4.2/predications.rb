require 'arel/predications'

module Arel
  module Predications
    def contained_within(other)
      Nodes::ContainedWithin.new self, Nodes.build_quoted(other, self)
    end

    def contained_within_or_equals(other)
      Nodes::ContainedWithinEquals.new self, Nodes.build_quoted(other, self)
    end

    def contains(other)
      Nodes::Contains.new self, Nodes.build_quoted(other, self)
    end

    def contained_in_array(other)
      Nodes::ContainedInArray.new self, Nodes.build_quoted(other, self)
    end

    def contains_or_equals(other)
      Nodes::ContainsEquals.new self, Nodes.build_quoted(other, self)
    end

    def overlap(other)
      Nodes::Overlap.new self, Nodes.build_quoted(other, self)
    end

    def any(other)
      any_tags_function = Arel::Nodes::NamedFunction.new('ANY', [self])
      Arel::Nodes::Equality.new(Nodes.build_quoted(other, self), any_tags_function)
    end

    def all(other)
      any_tags_function = Arel::Nodes::NamedFunction.new('ALL', [self])
      Arel::Nodes::Equality.new(Nodes.build_quoted(other, self), any_tags_function)
    end
  end
end
