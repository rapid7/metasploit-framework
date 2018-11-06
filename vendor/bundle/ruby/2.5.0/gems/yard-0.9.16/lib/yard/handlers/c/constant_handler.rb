# frozen_string_literal: true
class YARD::Handlers::C::ConstantHandler < YARD::Handlers::C::Base
  MATCH = /\brb_define_((?:readonly_)?variable|(?:global_)?const)
                \s*\((?:\s*(\w+),)?\s*"(\w+)",\s*(.*?)\s*\)\s*;/xm
  handles MATCH
  statement_class BodyStatement

  process do
    statement.source.scan(MATCH) do |type, var_name, const_name, value|
      handle_constants(type, var_name, const_name, value)
    end
  end
end
