# frozen_string_literal: true
module YARD
  module Handlers
    module Ruby
      module DSLHandlerMethods
        include CodeObjects
        include Parser

        IGNORE_METHODS = Hash[*%w(alias alias_method autoload attr attr_accessor
          attr_reader attr_writer extend include public private protected
          private_constant).map {|n| [n, true] }.flatten]

        def handle_comments
          return if IGNORE_METHODS[caller_method]

          @docstring = statement.comments || ""
          @docstring = @docstring.join("\n") if @docstring.is_a?(Array)

          attaching = false
          if @docstring =~ /^@!?macro\s+\[[^\]]*attach/
            register_docstring(nil)
            @docstring = ""
            attaching = true
          end

          macro = find_attached_macro
          if macro
            txt = macro.expand([caller_method, *call_params], statement.source)
            @docstring += "\n" + txt

            # macro may have a directive
            return register_docstring(nil) if !attaching && txt.match(/^\s*@!/)
          elsif !statement.comments_hash_flag && !implicit_docstring?
            return register_docstring(nil)
          end

          # ignore DSL definitions if @method/@attribute directive is used
          if @docstring =~ /^@!?(method|attribute)\b/
            return register_docstring(nil)
          end

          object = MethodObject.new(namespace, method_name, scope)
          object.signature = method_signature
          register(object)
        end

        def register_docstring(object, docstring = @docstring, stmt = statement)
          super
        end

        private

        def implicit_docstring?
          tags = %w(method attribute overload visibility scope return)
          tags.any? {|tag| @docstring =~ /^@!?#{tag}\b/ }
        end

        def method_name
          name = call_params.first || ""
          if name =~ /^#{CodeObjects::METHODNAMEMATCH}$/
            name
          else
            raise UndocumentableError, "method, missing name"
          end
        end

        def method_signature
          "def #{method_name}"
        end

        def find_attached_macro
          Registry.all(:macro).each do |macro|
            next unless macro.method_object
            next unless macro_name_matches(macro)
            (namespace.inheritance_tree(true) + [P('Object')]).each do |obj|
              return macro if obj == macro.method_object.namespace
            end
          end
          nil
        end

        # @return [Boolean] whether caller method matches a macro or
        #   its alias names.
        def macro_name_matches(macro)
          objs = [macro.method_object]
          if objs.first.type != :proxy && objs.first.respond_to?(:aliases)
            objs.concat(objs.first.aliases)
          end

          objs.any? {|obj| obj.name.to_s == caller_method.to_s }
        end
      end
    end
  end
end
