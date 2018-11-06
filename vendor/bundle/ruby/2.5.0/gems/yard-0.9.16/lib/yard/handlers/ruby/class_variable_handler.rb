# frozen_string_literal: true
# Handles a class variable (@@variable)
class YARD::Handlers::Ruby::ClassVariableHandler < YARD::Handlers::Ruby::Base
  handles :assign
  namespace_only

  process do
    if statement[0].type == :var_field && statement[0][0].type == :cvar
      name = statement[0][0][0]
      value = statement[1].source
      register ClassVariableObject.new(namespace, name) do |o|
        o.source = statement
        o.value = value
      end
    end
  end
end
