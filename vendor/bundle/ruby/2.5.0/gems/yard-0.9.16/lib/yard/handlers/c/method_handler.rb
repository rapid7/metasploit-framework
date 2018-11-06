# frozen_string_literal: true
class YARD::Handlers::C::MethodHandler < YARD::Handlers::C::Base
  MATCH1 = /rb_define_
                 (
                    singleton_method |
                    method           |
                    module_function  |
                    private_method
                 )
                 \s*\(\s*([\w\.]+)\s*,
                   \s*"([^"]+)"\s*,
                   \s*(?:RUBY_METHOD_FUNC\(|VALUEFUNC\(|\(\w+\))?(\w+)\)?\s*,
                   \s*(-?\w+)\s*\)/xm
  MATCH2 = /rb_define_global_function\s*\(
                \s*"([^"]+)",
                \s*(?:RUBY_METHOD_FUNC\(|VALUEFUNC\(|\(\w+\))?(\w+)\)?,
                \s*(-?\w+)\s*\)/xm
  handles MATCH1
  handles MATCH2
  statement_class BodyStatement

  process do
    statement.source.scan(MATCH1) do |type, var_name, name, func_name, _param_count|
      break if var_name == "ruby_top_self"
      break if var_name == "nstr"
      break if var_name == "envtbl"

      var_name = "rb_cObject" if var_name == "rb_mKernel"
      handle_method(type, var_name, name, func_name)
    end

    statement.source.scan(MATCH2) do |name, func_name, _param_count|
      handle_method("method", "rb_mKernel", name, func_name)
    end
  end
end
