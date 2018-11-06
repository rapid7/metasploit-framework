# frozen_string_literal: true
# (see Ruby::VisibilityHandler)
class YARD::Handlers::Ruby::Legacy::VisibilityHandler < YARD::Handlers::Ruby::Legacy::Base
  handles(/\A(protected|private|public)(\s|\(|$)/)
  namespace_only

  process do
    vis = statement.tokens.first.text
    if statement.tokens.size == 1
      self.visibility = vis
    else
      tokval_list(statement.tokens[2..-1], :attr).each do |name|
        MethodObject.new(namespace, name, scope) {|o| o.visibility = vis }
      end
    end
  end
end
