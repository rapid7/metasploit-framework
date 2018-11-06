# frozen_string_literal: true
# Helper methods to assist with processing decorators.
module YARD::Handlers::Ruby::DecoratorHandlerMethods
  # @overload process_decorator(*nodes, opts = {}, &block)
  #   Takes care of parsing method definitions passed to decorators
  #   as parameters, as well as parsing chained decorators.
  #
  #   Use this in a handler's process block.
  #
  #   @yieldparam method [YARD::CodeObjects::MethodObject] Method being decorated.
  #   @yieldparam node [YARD::Parser::Ruby::AstNode] AST node of the decorated method.
  #   @yieldparam name [Symbol] Name of the decorated method.
  #   @return [Array<Hash>] Array of hashes containing :method, :node, :name.
  #     See yield params.
  #
  #   @param nodes [YARD::Parser::Ruby::AstNode] AST nodes that refer to decorated
  #     methods, like indexes of statement.parameter. Defaults to all parameters.
  #     Pass nil to specify zero parameters.
  #
  #   @option opts [:instance, :class] :scope (:instance) Scope to use for each
  #     MethodObject.
  #
  #   @option opts [true, false] :transfer_docstring Set false to disable
  #     transferring the decorator docstring to method definitions passed to the
  #     decorator as parameters.
  #
  #   @option opts [true, false] :transfer_source Set false to disable
  #     transferring the decorator source code string to method definitions
  #     passed to the decorator as parameters.
  #
  #   @example Basic Usage
  #     # Simply pass the method docs through to the method definition.
  #     process do
  #       process_decorator
  #     end
  #
  #   @example Setting a method's visibility to private.
  #     process do
  #       process_decorator :scope => :class do |method|
  #         method.visibility = :private if method.respond_to? :visibility
  #       end
  #     end
  def process_decorator(*nodes, &block)
    opts = nodes.last.is_a?(Hash) ? nodes.pop : {}

    all_nodes = statement.parameters.select do |p|
      p.is_a? YARD::Parser::Ruby::AstNode
    end

    # Parse decorator parameters (decorator chain).
    all_nodes.each do |param|
      parse_block param if param.call? || param.def?
    end

    selected_nodes =
      if nodes.empty?
        all_nodes
      elsif nodes.count == 1 && nodes.first.nil?
        []
      else
        nodes
      end

    decorated_methods = selected_nodes.map do |param|
      process_decorator_parameter param, opts, &block
    end.flatten

    # Store method nodes in decorator node.
    statement.define_singleton_method :decorators do
      decorated_methods.map {|h| h[:node] }
    end

    decorated_methods
  end

  private

  def process_decorator_parameter(node, opts = {}, &block)
    scope              = opts.fetch :scope, :instance
    transfer_docstring = opts.fetch :transfer_docstring, true
    transfer_source    = opts.fetch :transfer_source, true

    name = nil

    if node.call?
      if node.respond_to? :decorators
        return node.decorators.map do |n|
          process_decorator_parameter n, opts, &block
        end
      end
    elsif node.def?
      name = node.jump(:def).method_name.source
    else
      name = node.jump(:ident, :string_content, :const).source
    end

    if name.nil?
      raise YARD::Parser::UndocumentableError, 'statement, cannot determine method name'
    end

    method = YARD::CodeObjects::Proxy.new(
      namespace,
      (scope == :instance ? '#' : '.') + name.to_s,
      :method
    )

    # Transfer source to methods passed to the helper as parameters.
    method.source = statement.source if transfer_source && node.def?

    # Transfer decorator docstring to methods passed to the helper as parameters.
    if transfer_docstring && node.def? &&
       statement.docstring && method.docstring.empty?
      tags = method.tags if method.respond_to? :tags
      tags ||= []
      method.docstring = statement.docstring
      tags.each {|t| method.add_tag t }
    end

    yield method, node, name.to_sym if block_given?

    [{:method => method, :node => node, :name => name.to_sym}]
  end
end
