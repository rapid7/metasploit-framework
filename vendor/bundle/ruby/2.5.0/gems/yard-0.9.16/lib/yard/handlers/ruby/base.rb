# frozen_string_literal: true
module YARD
  module Handlers
    module Ruby
      # To implement a custom handler matcher, subclass this class and implement
      # {#matches?} to return whether a node matches the handler.
      #
      # @example A Custom Handler Matcher Extension
      #   # Implements a handler that checks for a specific string
      #   # in the node's source.
      #   class MyExtension < HandlesExtension
      #     def matches?(node) node.source.include?(name) end
      #   end
      #
      #   # This handler will handle any node where the source includes 'foo'
      #   class MyHandler < Handlers::Ruby::Base
      #     handles MyExtension.new('foo')
      #   end
      class HandlesExtension
        # Creates a new extension with a specific matcher value +name+
        # @param [Object] name the matcher value to check against {#matches?}
        def initialize(name) @name = name end

        # Tests if the node matches the handler
        # @param [Parser::Ruby::AstNode] node a Ruby node
        # @return [Boolean] whether the +node+ matches the handler
        def matches?(node) # rubocop:disable Lint/UnusedMethodArgument
          raise NotImplementedError
        end

        protected

        # @return [String] the extension matcher value
        attr_reader :name
      end

      class MethodCallWrapper < HandlesExtension
        def matches?(node)
          case node.type
          when :var_ref
            if !node.parent || node.parent.type == :list
              return true if node[0].type == :ident && (name.nil? || node[0][0] == name)
            end
          when :fcall, :command, :vcall
            return true if name.nil? || node[0][0] == name
          when :call, :command_call
            return true if name.nil? || node[2][0] == name
          end
          false
        end
      end

      class TestNodeWrapper < HandlesExtension
        def matches?(node) !node.send(name).is_a?(FalseClass) end
      end

      # This is the base handler class for the new-style (1.9) Ruby parser.
      # All handlers that subclass this base class will be used when the
      # new-style parser is used. For implementing legacy handlers, see
      # {Legacy::Base}.
      #
      # @abstract See {Handlers::Base} for subclassing information.
      # @see Handlers::Base
      # @see Legacy::Base
      class Base < Handlers::Base
        class << self
          include Parser::Ruby

          # @group Statement Matcher Extensions

          # Matcher for handling any type of method call. Method calls can
          # be expressed by many {AstNode} types depending on the syntax
          # with which it is called, so YARD allows you to use this matcher
          # to simplify matching a method call.
          #
          # @example Match the "describe" method call
          #   handles method_call(:describe)
          #
          #   # The following will be matched:
          #   # describe(...)
          #   # object.describe(...)
          #   # describe "argument" do ... end
          #
          # @param [#to_s] name matches the method call of this name
          # @return [void]
          def method_call(name = nil)
            MethodCallWrapper.new(name ? name.to_s : nil)
          end

          # Matcher for handling a node with a specific meta-type. An {AstNode}
          # has a {AstNode#type} to define its type but can also be associated
          # with a set of types. For instance, +:if+ and +:unless+ are both
          # of the meta-type +:condition+.
          #
          # A meta-type is any method on the {AstNode} class ending in "?",
          # though you should not include the "?" suffix in your declaration.
          # Some examples are: "condition", "call", "literal", "kw", "token",
          # "ref".
          #
          # @example Handling any conditional statement (if, unless)
          #   handles meta_type(:condition)
          # @param [Symbol] type the meta-type to match. A meta-type can be
          #   any method name + "?" that {AstNode} responds to.
          # @return [void]
          def meta_type(type)
            TestNodeWrapper.new(type.to_s + "?")
          end

          # @group Testing for a Handler

          # @return [Boolean] whether or not an {AstNode} object should be
          #   handled by this handler
          def handles?(node)
            handlers.any? do |a_handler|
              case a_handler
              when Symbol
                a_handler == node.type
              when String
                node.source == a_handler
              when Regexp
                node.source =~ a_handler
              when Parser::Ruby::AstNode
                a_handler == node
              when HandlesExtension
                a_handler.matches?(node)
              end
            end
          end
        end

        include Parser::Ruby

        # @group Parsing an Inner Block

        def parse_block(inner_node, opts = {})
          push_state(opts) do
            nodes = inner_node.type == :list ? inner_node.children : [inner_node]
            parser.process(nodes)
          end
        end

        # @group Macro Handling

        def call_params
          return [] unless statement.respond_to?(:parameters)
          statement.parameters(false).compact.map do |param|
            if param.type == :list
              param.map {|n| n.jump(:ident, :kw, :tstring_content).source }
            else
              param.jump(:ident, :kw, :tstring_content).source
            end
          end.flatten
        end

        def caller_method
          if statement.call? || statement.def?
            statement.method_name(true).to_s
          elsif statement.type == :var_ref || statement.type == :vcall
            statement[0].jump(:ident, :kw).source
          end
        end
      end
    end
  end
end
