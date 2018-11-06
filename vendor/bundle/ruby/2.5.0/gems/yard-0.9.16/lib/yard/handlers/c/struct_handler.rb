# frozen_string_literal: true
class YARD::Handlers::C::StructHandler < YARD::Handlers::C::Base
  MATCH = /([\w\.]+)\s*=\s*(?:rb_struct_define_without_accessor)\s*
           \(\s*"([\w:]+)"\s*,\s*(\w+)\s*/mx
  handles MATCH
  statement_class BodyStatement

  process do
    statement.source.scan(MATCH) do |var_name, class_name, parent|
      handle_class(var_name, class_name, parent)
    end
  end
end
