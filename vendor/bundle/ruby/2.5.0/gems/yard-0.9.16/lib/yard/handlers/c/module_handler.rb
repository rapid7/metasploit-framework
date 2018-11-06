# frozen_string_literal: true
class YARD::Handlers::C::ModuleHandler < YARD::Handlers::C::Base
  MATCH1 = /([\w\.]+)\s* = \s*rb_define_module\s*\(\s*"([\w:]+)"\s*\)/mx
  MATCH2 = /([\w\.]+)\s* = \s*rb_define_module_under\s*\(\s*(\w+),\s*"(\w+)"\s*\)/mx
  handles MATCH1
  handles MATCH2
  statement_class BodyStatement

  process do
    statement.source.scan(MATCH1) do |var_name, module_name|
      handle_module(var_name, module_name)
    end
    statement.source.scan(MATCH2) do |var_name, in_module, module_name|
      handle_module(var_name, module_name, in_module)
    end
  end
end
