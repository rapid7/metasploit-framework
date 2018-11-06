# frozen_string_literal: true
class YARD::Handlers::C::ClassHandler < YARD::Handlers::C::Base
  MATCH1 = /([\w\.]+)\s* = \s*(?:rb_define_class|boot_defclass)\s*
            \(
               \s*"([\w:]+)",
               \s*(\w+|0)\s*
            \)/mx

  MATCH2 = /([\w\.]+)\s* = \s*rb_define_class_under\s*
            \(
               \s*(\w+),
               \s*"(\w+)"(?:,
               \s*([\w\*\s\(\)\.\->]+)\s*)?  # for SWIG
            \s*\)/mx
  handles MATCH1
  handles MATCH2
  statement_class BodyStatement

  process do
    statement.source.scan(MATCH1) do |var_name, class_name, parent|
      handle_class(var_name, class_name, parent)
    end
    statement.source.scan(MATCH2) do |var_name, in_module, class_name, parent|
      handle_class(var_name, class_name, parent.strip, in_module)
    end
  end
end
