# frozen_string_literal: true
module YARD
  module Parser
    module Ruby
      # Builds and s-expression by creating {AstNode} objects with
      # the type provided by the first argument.
      #
      # @example An implicit list of keywords
      #   ast = s(s(:kw, "if"), s(:kw, "else"))
      #   ast.type # => :list
      # @example A method call
      #   s(:command, s(:var_ref, "mymethod"))
      #
      # @overload s(*nodes, opts = {})
      #   @param [Array<AstNode>] nodes a list of nodes.
      #   @param [Hash] opts any extra options (docstring, file, source) to
      #     set on the object
      #   @return [AstNode] an implicit node where node.type == +:list+
      # @overload s(type, *children, opts = {})
      #   @param [Symbol] type the node type
      #   @param [Array<AstNode>] children any child nodes inside this one
      #   @param [Hash] opts any extra options to set on the object
      #   @return [AstNode] a node of type +type+.
      # @see AstNode#initialize
      def s(*args)
        type = Symbol === args.first ? args.shift : :list
        opts = Hash === args.last ? args.pop : {}
        AstNode.node_class_for(type).new(type, args, opts)
      end

      # An AST node is characterized by a type and a list of children. It
      # is most easily represented by the s-expression {#s} such as:
      #   # AST for "if true; 5 end":
      #   s(s(:if, s(:var_ref, s(:kw, "true")), s(s(:int, "5")), nil))
      #
      # The node type is not considered part of the list, only its children.
      # So +ast[0]+ does not refer to the type, but rather the first child
      # (or object). Items that are not +AstNode+ objects can be part of the
      # list, like Strings or Symbols representing names. To return only
      # the AstNode children of the node, use {#children}.
      class AstNode < Array
        attr_accessor :docstring_hash_flag
        attr_accessor :docstring, :docstring_range, :source

        # @deprecated Groups are now defined by directives
        # @see Tags::GroupDirective
        attr_accessor :group

        attr_writer :source_range, :line_range, :file, :full_source
        alias comments docstring
        alias comments_range docstring_range
        alias comments_hash_flag docstring_hash_flag
        alias to_s source

        # @return [Symbol] the node's unique symbolic type
        attr_accessor :type

        # @return [AstNode, nil] the node's parent or nil if it is a root node.
        attr_accessor :parent

        # @return [Range] the character range in {#full_source} represented
        #   by the node
        def source_range
          reset_line_info unless @source_range
          @source_range
        end

        # @return [Range] the line range in {#full_source} represented
        #   by the node
        def line_range
          reset_line_info unless @line_range
          @line_range
        end

        # @return [String] the filename the node was parsed from
        def file
          return parent.file if parent
          @file
        end

        # @return [String] the full source that the node was parsed from
        def full_source
          return parent.full_source if parent
          return @full_source if @full_source
          return IO.read(@file) if file && File.exist?(file)
        end

        # @return [String] the parse of {#full_source} that the node represents
        def source
          return parent.full_source[source_range] if parent
          full_source
        end

        # List of all known keywords
        # @return [Hash]
        KEYWORDS = {:class => true, :alias => true, :lambda => true, :do_block => true,
          :def => true, :defs => true, :begin => true, :rescue => true, :rescue_mod => true,
          :if => true, :if_mod => true, :else => true, :elsif => true, :case => true,
          :when => true, :next => true, :break => true, :retry => true, :redo => true,
          :return => true, :throw => true, :catch => true, :until => true, :until_mod => true,
          :while => true, :while_mod => true, :yield => true, :yield0 => true, :zsuper => true,
          :unless => true, :unless_mod => true, :for => true, :super => true, :return0 => true}

        # @group Creating an AstNode

        # Finds the node subclass that should be instantiated for a specific
        # node type
        #
        # @param [Symbol] type the node type to find a subclass for
        # @return [Class] a subclass of AstNode to instantiate the node with.
        def self.node_class_for(type)
          case type
          when :params
            ParameterNode
          when :call, :fcall, :vcall, :command, :command_call
            MethodCallNode
          when :if, :elsif, :if_mod, :unless, :unless_mod
            ConditionalNode
          when :for, :while, :while_mod, :until, :until_mod
            LoopNode
          when :def, :defs
            MethodDefinitionNode
          when :class, :sclass
            ClassNode
          when :module
            ModuleNode
          else
            if type.to_s =~ /_ref\Z/
              ReferenceNode
            elsif type.to_s =~ /_literal\Z/
              LiteralNode
            elsif KEYWORDS.key?(type)
              KeywordNode
            else
              AstNode
            end
          end
        end

        # Creates a new AST node
        #
        # @param [Symbol] type the type of node being created
        # @param [Array<AstNode>] arr the child nodes
        # @param [Hash] opts any extra line options
        # @option opts [Fixnum] :line (nil) the line the node starts on in source
        # @option opts [String] :char (nil) the character number the node starts on
        #   in source
        # @option opts [Fixnum] :listline (nil) a special key like :line but for
        #   list nodes
        # @option opts [Fixnum] :listchar (nil) a special key like :char but for
        #   list nodes
        # @option opts [Boolean] :token (nil) whether the node represents a token
        def initialize(type, arr, opts = {})
          super(arr)
          self.type = type
          self.line_range = opts[:line]
          self.source_range = opts[:char]
          @fallback_line = opts[:listline]
          @fallback_source = opts[:listchar]
          @token = true if opts[:token]
          @docstring = nil
        end

        # @return [Boolean] whether the node is equal to another by checking
        #   the list and type
        # @private
        def ==(other)
          super && type == other.type
        end

        # @group Traversing a Node

        # Searches through the node and all descendants and returns the
        # first node with a type matching any of +node_types+, otherwise
        # returns the original node (self).
        #
        # @example Returns the first method definition in a block of code
        #   ast = YARD.parse_string("if true; def x; end end").ast
        #   ast.jump(:def)
        #   # => s(:def, s(:ident, "x"), s(:params, nil, nil, nil, nil,
        #   #      nil), s(s(:void_stmt, )))
        # @example Returns first 'def' or 'class' statement
        #   ast = YARD.parse_string("class X; def y; end end")
        #   ast.jump(:def, :class).first
        #   # =>
        # @example If the node types are not present in the AST
        #   ast = YARD.parse("def x; end")
        #   ast.jump(:def)
        #
        # @param [Array<Symbol>] node_types a set of node types to match
        # @return [AstNode] the matching node, if one was found
        # @return [self] if no node was found
        def jump(*node_types)
          traverse {|child| return(child) if node_types.include?(child.type) }
          self
        end

        # @return [Array<AstNode>] the {AstNode} children inside the node
        def children
          @children ||= select {|e| AstNode === e }
        end

        # Traverses the object and yields each node (including descendants) in order.
        #
        # @yield each descendant node in order
        # @yieldparam [AstNode] self, or a child/descendant node
        # @return [void]
        def traverse
          nodes = [self]
          until nodes.empty?
            node = nodes.pop
            yield node
            nodes += node.children.reverse unless node.children.empty?
          end
        end

        # @group Node Meta Types

        # @return [Boolean] whether the node is a token
        def token?
          @token
        end

        # @return [Boolean] whether the node is a reference (variable,
        #   constant name)
        def ref?
          false
        end

        # @return [Boolean] whether the node is a literal value
        def literal?
          false
        end

        # @return [Boolean] whether the node is a keyword
        def kw?
          false
        end

        # @return [Boolean] whether the node is a method call
        def call?
          false
        end

        # @return [Boolean] whether the node is a method definition
        def def?
          false
        end

        # @return [Boolean] whether the node is a if/elsif/else condition
        def condition?
          false
        end

        # @return [Boolean] whether the node is a loop
        def loop?
          false
        end

        # @return [Boolean] whether the node has a block
        def block?
          respond_to?(:block) || condition?
        end

        # @group Getting Line Information

        # @return [Boolean] whether the node has a {#line_range} set
        def has_line?
          @line_range ? true : false
        end

        # @return [Fixnum] the starting line number of the node
        def line
          line_range && line_range.first
        end

        # @return [String] the first line of source represented by the node.
        def first_line
          full_source.split(/\r?\n/)[line - 1].strip
        end

        # @group Printing a Node

        # @return [String] the first line of source the node represents
        def show
          "\t#{line}: #{first_line}"
        end

        # @return [nil] pretty prints the node
        def pretty_print(q)
          objs = dup + [:__last__]
          objs.unshift(type) if type && type != :list

          options = []
          options << ['docstring', docstring] if @docstring
          if @source_range || @line_range
            options << ['line', line_range]
            options << ['source', source_range]
          end
          objs.pop if options.empty?

          q.group(3, 's(', ')') do
            q.seplist(objs, nil, :each) do |v|
              if v == :__last__
                q.seplist(options, nil, :each) do |arr|
                  k, v2 = *arr
                  q.group(3) do
                    q.text k
                    q.group(3) do
                      q.text ': '
                      q.pp v2
                    end
                  end
                end
              else
                q.pp v
              end
            end
          end
        end

        # @return [String] inspects the object
        def inspect
          typeinfo = type && type != :list ? ':' + type.to_s + ', ' : ''
          's(' + typeinfo + map(&:inspect).join(", ") + ')'
        end

        # @group Managing node state

        # Resets node state in tree
        def unfreeze
          @children = nil
        end

        # @endgroup

        private

        # Resets line information
        # @return [void]
        def reset_line_info
          if size == 0
            self.line_range = @fallback_line
            self.source_range = @fallback_source
          elsif !children.empty?
            f = children.first
            l = children.last
            self.line_range = Range.new(f.line_range.first, l.line_range.last)
            self.source_range = Range.new(f.source_range.first, l.source_range.last)
          elsif @fallback_line || @fallback_source
            self.line_range = @fallback_line
            self.source_range = @fallback_source
          else
            self.line_range = 0...0
            self.source_range = 0...0
          end
        end
      end

      class ReferenceNode < AstNode
        def ref?; true end

        def path
          Array.new flatten
        end

        def namespace
          Array.new flatten[0...-1]
        end
      end

      class LiteralNode < AstNode
        def literal?; true end
      end

      class KeywordNode < AstNode
        def kw?; true end
      end

      class ParameterNode < AstNode
        def unnamed_required_params
          self[0]
        end

        def unnamed_optional_params
          return @unnamed_optional_params if defined?(@unnamed_optional_params)

          params = self[1] || []
          if self[-3] && self[-3][0] && self[-3][0].type == :unnamed_optional_arg
            params += self[-3]
          end

          @unnamed_optional_params = params.empty? ? nil : params
        end

        def named_params
          return @named_params if defined?(@named_params)

          if YARD.ruby2? && self[-3] && self[-3][0] && self[-3][0].type == :named_arg
            @named_params = self[-3]
          else
            @named_params = nil
          end
        end

        def splat_param
          self[2] ? self[2][0] : nil
        end

        def unnamed_end_params
          self[3]
        end

        def double_splat_param
          return nil unless YARD.ruby2?
          if (node = self[-2]).is_a?(AstNode)
            if node.type == :ident
              node
            elsif node.type == :kwrest_param
              # See https://bugs.ruby-lang.org/issues/12387
              node.last
            end
          end
        end

        def block_param
          self[-1] ? self[-1][0] : nil
        end
      end

      class MethodCallNode < AstNode
        def call?; true end
        def namespace; first if index_adjust > 0 end

        def method_name(name_only = false)
          name = self[index_adjust]
          if name == :call
            nil
          elsif name_only && Array === name
            name.jump(:ident).first.to_sym
          else
            name
          end
        end

        def parameters(include_block_param = true)
          return [] if type == :vcall
          params = self[1 + index_adjust]
          return [] unless params
          params = call_has_paren? ? params.first : params
          return [] unless params
          include_block_param ? params : params[0...-1]
        end

        def block_param; parameters.last end

        def block
          last.type == :do_block || last.type == :brace_block ? last : nil
        end

        private

        def index_adjust
          [:call, :command_call].include?(type) ? 2 : 0
        end

        def call_has_paren?
          [:fcall, :call].include?(type)
        end
      end

      class MethodDefinitionNode < AstNode
        def kw?; true end
        def def?; true end
        def namespace; first if index_adjust > 0 end

        def method_name(name_only = false)
          name = self[index_adjust]
          name_only ? name.jump(:ident).first.to_sym : name
        end

        def parameters(include_block_param = true)
          params = self[1 + index_adjust]
          params = params[0] if params.type == :paren
          include_block_param ? params : params[0...-1]
        end

        alias block last

        private

        def index_adjust
          type == :defs ? 2 : 0
        end
      end

      class ConditionalNode < KeywordNode
        def condition?; true end
        def condition; first end
        def then_block; self[1] end

        def else_block
          return unless self[2] && !cmod?
          self[2].type == :elsif ? self[2] : self[2][0]
        end

        private

        def cmod?; type =~ /_mod$/ end
      end

      class ClassNode < KeywordNode
        def class_name; first end
        def superclass; type == :sclass ? nil : self[1] end
        def block; last end
      end

      class ModuleNode < KeywordNode
        def module_name; first end
        def block; last end
      end

      class LoopNode < KeywordNode
        def loop?; true end
        def condition; type == :for ? s(self[0], self[1]) : first end
        def block; last end
      end

      # Represents a lone comment block in source
      class CommentNode < AstNode
        def docstring; first end
        def docstring=(value) end
        alias comments docstring

        def source; "" end
        def first_line; "" end
      end
    end
  end
end
