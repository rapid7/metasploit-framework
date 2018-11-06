module RKelly
  module Visitors
    class RealSexpVisitor < Visitor
      ALL_NODES.each do |type|
        eval <<-RUBY
          def visit_#{type}Node(o)
            sexp = s(:#{type.scan(/[A-Z][a-z]+/).join('_').downcase}, *super(o))
            sexp.line = o.line if o.line
            sexp.file = o.filename
            sexp
          end
        RUBY
      end
    end
  end
end
