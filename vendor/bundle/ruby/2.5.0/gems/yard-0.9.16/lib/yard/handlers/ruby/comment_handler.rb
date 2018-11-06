# frozen_string_literal: true
# Handles any lone comment statement in a Ruby file
class YARD::Handlers::Ruby::CommentHandler < YARD::Handlers::Ruby::Base
  handles :comment, :void_stmt
  namespace_only

  process do
    register_docstring(nil)
  end
end
