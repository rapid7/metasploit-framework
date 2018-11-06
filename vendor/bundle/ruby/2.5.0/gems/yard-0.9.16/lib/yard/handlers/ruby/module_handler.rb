# frozen_string_literal: true
# Handles the declaration of a module
class YARD::Handlers::Ruby::ModuleHandler < YARD::Handlers::Ruby::Base
  handles :module
  namespace_only

  process do
    modname = statement[0].source
    mod = register ModuleObject.new(namespace, modname)
    parse_block(statement[1], :namespace => mod)
  end
end
