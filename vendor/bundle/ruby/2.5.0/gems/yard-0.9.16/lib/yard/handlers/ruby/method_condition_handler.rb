# frozen_string_literal: true
# Handles a conditional inside a method
class YARD::Handlers::Ruby::MethodConditionHandler < YARD::Handlers::Ruby::Base
  handles :if_mod, :unless_mod

  process do
    parse_block(statement.then_block, :owner => owner)
  end
end
