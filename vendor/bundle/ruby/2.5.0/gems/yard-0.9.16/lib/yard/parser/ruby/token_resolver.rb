# frozen_string_literal: true
module YARD
  module Parser
    module Ruby
      # Supports {#each} enumeration over a source's tokens, yielding
      # the token and a possible {CodeObjects::Base} associated with the
      # constant or identifier token.
      class TokenResolver
        include Enumerable

        # Creates a token resolver for given source.
        #
        # @param source [String] the source code to tokenize
        # @param namespace [CodeObjects::Base] the object/namespace to resolve from
        def initialize(source, namespace = Registry.root)
          @tokens = RubyParser.parse(source, '(tokenize)').tokens
          raise ParserSyntaxError if @tokens.empty? && !source.empty?
          @default_namespace = namespace
        end

        # Iterates over each token, yielding the token and a possible code
        # object that is associated with the token.
        #
        # @yieldparam token [Array(Symbol,String,Array(Integer,Integer))] the
        #   current token object being iterated
        # @yieldparam object [CodeObjects::Base, nil] the fully qualified code
        #   object associated with the current token, or nil if there is no object
        #   for the yielded token.
        # @example Yielding code objects
        #   r = TokenResolver.new("A::B::C")
        #   r.each do |tok, obj|
        #     if obj
        #       puts "#{tok[0]} -> #{obj.path.inspect}"
        #     else
        #       puts "No object: #{tok.inspect}"
        #     end
        #   end
        #
        #   # Prints:
        #   # :const -> "A"
        #   # No object: [:op, "::"]
        #   # :const -> "A::B"
        #   # No object: [:op, "::"]
        #   # :const -> "A::B::C"
        def each
          @states = []
          push_state
          @tokens.each do |token|
            yield_obj = false

            if skip_group && [:const, :ident, :op, :period].include?(token[0])
              yield token, nil
              next
            else
              self.skip_group = false
            end

            case token[0]
            when :const
              lookup(token[0], token[1])
              yield_obj = true
              self.last_sep = nil
            when :ident
              lookup(token[0], token[1])
              yield_obj = true
              self.last_sep = nil
            when :op, :period
              self.last_sep = token[1]
              unless CodeObjects.types_for_separator(token[1])
                self.object = nil
                self.last_sep = nil
              end
            when :lparen
              push_state
            when :rparen
              pop_state
            else
              self.object = nil
            end

            yield token, (yield_obj ? object : nil)

            if next_object
              self.object = next_object
              self.next_object = nil
            end
            self.skip_group = true if yield_obj && object.nil?
          end
        end

        def self.state_attr(*attrs)
          attrs.each do |attr|
            define_method(attr) { @states.last[attr.to_sym] }
            define_method("#{attr}=") {|v| @states.last[attr.to_sym] = v }
            protected attr, :"#{attr}="
          end
        end

        private

        def push_state
          @states.push :object => nil, :skip_group => false, :last_sep => nil
        end

        def pop_state
          @states.pop
        end

        state_attr :object, :next_object, :skip_group, :last_sep

        def lookup(toktype, name)
          types = object_resolved_types
          return self.object = nil if types.empty?

          if toktype == :const
            types.any? do |type|
              prefix = (type ? type.path : "") + last_sep.to_s
              self.object = Registry.resolve(@default_namespace, "#{prefix}#{name}", true)
            end
          else # ident
            types.any? do |type|
              obj = Registry.resolve(type, name, true)
              if obj.nil? && name == "new"
                obj = Registry.resolve(object, "#initialize", true)
                self.next_object = object if obj.nil?
              end
              self.object = obj
            end
          end
        end

        def object_resolved_types(obj = object)
          return [obj] unless obj.is_a?(CodeObjects::MethodObject)

          resolved_types = []
          tags = obj.tags(:return)
          tags += obj.tags(:overload).map {|o| o.tags(:return) }.flatten
          tags.each do |tag|
            next if tag.types.nil?
            tag.types.each do |type|
              type = type.sub(/<.+>/, '')
              if type == "self"
                resolved_types << obj.parent
              else
                type_obj = Registry.resolve(obj, type, true)
                resolved_types << type_obj if type_obj
              end
            end
          end

          resolved_types
        end
      end
    end
  end
end
