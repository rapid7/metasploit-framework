# frozen_string_literal: true
# (see Ruby::ExtendHandler)
class YARD::Handlers::Ruby::Legacy::ExtendHandler < YARD::Handlers::Ruby::Legacy::MixinHandler
  handles(/\Aextend(\s|\()/)
  namespace_only

  def scope; :class end

  private

  def process_mixin(mixin)
    if mixin == "self"
      if namespace.is_a?(ClassObject)
        raise UndocumentableError, "extend(self) statement on class"
      end
      namespace.mixins(scope) << namespace
    else
      super
    end
  end
end
