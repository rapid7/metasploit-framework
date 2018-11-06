# frozen_string_literal: true
# (see Ruby::PrivateConstantHandler)
class YARD::Handlers::Ruby::Legacy::PrivateConstantHandler < YARD::Handlers::Ruby::Legacy::Base
  handles(/\Aprivate_constant(\s|\(|$)/)
  namespace_only

  process do
    tokval_list(statement.tokens[2..-1], :attr, TkCONSTANT).each do |name|
      privatize_constant name
    end
  end

  private

  def privatize_constant(name)
    const = Proxy.new(namespace, name)
    ensure_loaded!(const)
    const.visibility = :private
  rescue NamespaceMissingError
    raise UndocumentableError, "private visibility set on unrecognized constant: #{name}"
  end
end
