# frozen_string_literal: true
class YARD::Handlers::C::MixinHandler < YARD::Handlers::C::Base
  MATCH = /rb_include_module\s*\(\s*(\w+?),\s*(\w+?)\s*\)/
  handles MATCH
  statement_class BodyStatement

  process do
    statement.source.scan(MATCH) do |klass_var, mixin_var|
      namespace = namespace_for_variable(klass_var)
      ensure_loaded!(namespace)

      var = namespace_for_variable(mixin_var)
      if var
        namespace.mixins(:instance) << var
      else
        raise YARD::Parser::UndocumentableError,
          "CRuby mixin for unrecognized variable '#{mixin_var}'"
      end
    end
  end
end
