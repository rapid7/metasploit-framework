# frozen_string_literal: true
# (see Ruby::ModuleHandler)
class YARD::Handlers::Ruby::Legacy::ModuleHandler < YARD::Handlers::Ruby::Legacy::Base
  handles TkMODULE
  namespace_only

  process do
    modname = statement.tokens.to_s[/^module\s+(#{NAMESPACEMATCH})/, 1]
    mod = register ModuleObject.new(namespace, modname)
    parse_block(:namespace => mod)
  end
end
