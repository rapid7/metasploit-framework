# frozen_string_literal: true
# (see Ruby::ClassVariableHandler)
class YARD::Handlers::Ruby::Legacy::ClassVariableHandler < YARD::Handlers::Ruby::Legacy::Base
  HANDLER_MATCH = /\A@@\w+\s*=\s*/m
  handles HANDLER_MATCH
  namespace_only

  process do
    name, value = *statement.tokens.to_s.split(/\s*=\s*/, 2)
    register ClassVariableObject.new(namespace, name) do |o|
      o.source = statement
      o.value = value.strip
    end
  end
end
