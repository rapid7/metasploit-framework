# frozen_string_literal: true
class YARD::Handlers::C::AliasHandler < YARD::Handlers::C::Base
  MATCH = /rb_define_alias
             \s*\(\s*([\w\.]+),
             \s*"([^"]+)",
             \s*"([^"]+)"\s*\)/xm
  handles MATCH
  statement_class BodyStatement

  process do
    statement.source.scan(MATCH) do |var_name, new_name, old_name|
      var_name = "rb_cObject" if var_name == "rb_mKernel"
      handle_alias(var_name, new_name, old_name)
    end
  end
end
