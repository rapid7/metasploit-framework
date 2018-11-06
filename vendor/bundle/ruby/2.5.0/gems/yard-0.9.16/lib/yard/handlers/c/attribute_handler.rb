# frozen_string_literal: true
class YARD::Handlers::C::AttributeHandler < YARD::Handlers::C::Base
  MATCH = /rb_define_attr\s*\(\s*([\w\.]+),\s*"([^"]+)",\s*(0|1)\s*,\s*(0|1)\s*\)/
  handles MATCH

  process do
    return if ToplevelStatement == statement
    return if Comment === statement && statement.type != :multi
    statement.source.scan(MATCH) do |var_name, name, read, write|
      handle_attribute(var_name, name, read, write)
    end
  end
end
