# frozen_string_literal: true
class YARD::Handlers::C::PathHandler < YARD::Handlers::C::Base
  MATCH = /([\w\.]+)\s* = \s*rb_path2class\s*\(\s*"([\w:]+)"\)/mx
  handles MATCH

  process do
    statement.source.scan(MATCH) do |var_name, path|
      namespaces[var_name] = P(path)
    end
  end
end
