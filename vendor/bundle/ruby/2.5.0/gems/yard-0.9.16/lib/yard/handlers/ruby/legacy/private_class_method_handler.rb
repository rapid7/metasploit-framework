# frozen_string_literal: true
# (see Ruby::PrivateClassMethodHandler)
class YARD::Handlers::Ruby::Legacy::PrivateClassMethodHandler < YARD::Handlers::Ruby::Legacy::Base
  handles(/\Aprivate_class_method(\s|\(|$)/)
  namespace_only

  process do
    tokval_list(statement.tokens[2..-1], :attr).each do |name|
      privatize_class_method name
    end
  end

  private

  def privatize_class_method(name)
    method = Proxy.new(namespace, name)
    ensure_loaded!(method)
    method.visibility = :private
  rescue YARD::Handlers::NamespaceMissingError
    raise UndocumentableError, "private visibility set on unrecognized method: #{name}"
  end
end
