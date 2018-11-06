# frozen_string_literal: true
module YARD
  module Handlers
    module C
      module HandlerMethods
        include Parser::C
        include CodeObjects

        def handle_class(var_name, class_name, parent, in_module = nil)
          parent = nil if parent == "0"
          namespace = in_module ? ensure_variable_defined!(in_module) : Registry.root
          if namespace.nil?
            raise Parser::UndocumentableError,
              "class #{class_name}. Cannot find definition for parent namespace."
          end

          register ClassObject.new(namespace, class_name) do |obj|
            if parent
              parent_class = namespace_for_variable(parent)
              if parent_class.is_a?(Proxy)
                obj.superclass = "::#{parent_class.path}"
                obj.superclass.type = :class
              else
                obj.superclass = parent_class
              end
            end
            namespaces[var_name] = obj
            register_file_info(obj, statement.file, statement.line)
          end
        end

        def handle_module(var_name, module_name, in_module = nil)
          namespace = in_module ? ensure_variable_defined!(in_module) : Registry.root
          if namespace.nil?
            raise Parser::UndocumentableError,
              "module #{module_name}. Cannot find definition for parent namespace."
          end

          register ModuleObject.new(namespace, module_name) do |obj|
            namespaces[var_name] = obj
            register_file_info(obj, statement.file, statement.line)
          end
        end

        def handle_method(scope, var_name, name, func_name, _source_file = nil)
          visibility = :public
          case scope
          when "singleton_method"; scope = :class
          when "module_function"; scope = :module
          when "private_method"; scope = :instance; visibility = :private
          else; scope = :instance
          end

          namespace = namespace_for_variable(var_name)

          # Is this method being defined on a core Ruby class or module?
          if namespace.is_a?(Proxy)
            if var_name =~ /^rb_c(\w+)/ && YARD::CodeObjects::BUILTIN_CLASSES.include?($1)
              namespace = namespaces[var_name] = YARD::CodeObjects::ClassObject.new(:root, $1)
            elsif var_name =~ /^rb_m(\w+)/ && YARD::CodeObjects::BUILTIN_MODULES.include?($1)
              namespace = namespaces[var_name] = YARD::CodeObjects::ModuleObject.new(:root, $1)
            end
          end

          return if namespace.nil? # XXX: raise UndocumentableError might be too noisy.
          register MethodObject.new(namespace, name, scope) do |obj|
            register_visibility(obj, visibility)
            find_method_body(obj, func_name)
            obj.explicit = true
            obj.add_tag(Tags::Tag.new(:return, '', 'Boolean')) if name =~ /\?$/
          end
        end

        def handle_attribute(var_name, name, read, write)
          values = {:read => read.to_i, :write => write.to_i}
          {:read => name, :write => "#{name}="}.each do |type, meth_name|
            next unless values[type] > 0
            obj = handle_method(:instance, var_name, meth_name, nil)
            register_file_info(obj, statement.file, statement.line)
            obj.namespace.attributes[:instance][name] ||= SymbolHash[:read => nil, :write => nil]
            obj.namespace.attributes[:instance][name][type] = obj
          end
        end

        def handle_alias(var_name, new_name, old_name)
          namespace = namespace_for_variable(var_name)
          return if namespace.nil?
          new_meth = new_name.to_sym
          old_meth = old_name.to_sym
          old_obj = namespace.child(:name => old_meth, :scope => :instance)
          new_obj = register MethodObject.new(namespace, new_meth, :instance) do |o|
            register_visibility(o, visibility)
            register_file_info(o, statement.file, statement.line)
          end

          if old_obj
            new_obj.signature = old_obj.signature
            new_obj.source = old_obj.source
            new_obj.docstring = old_obj.docstring
            new_obj.docstring.object = new_obj
          else
            new_obj.signature = "def #{new_meth}" # this is all we know.
          end

          namespace.aliases[new_obj] = old_meth
        end

        def handle_constants(type, var_name, const_name, value)
          return unless type =~ /^const$|^global_const$/
          namespace = type == 'global_const' ?
            :root : namespace_for_variable(var_name)
          register ConstantObject.new(namespace, const_name) do |obj|
            obj.source_type = :c
            obj.value = value
            register_file_info(obj, statement.file, statement.line)
            find_constant_docstring(obj)
          end
        end

        private

        def find_constant_docstring(object)
          comment = nil

          # look inside overrides for declaration value
          override_comments.each do |name, override_comment|
            next unless override_comment.file == statement.file
            just_const_name = name.gsub(/\A.+::/, '')
            if object.path == name || object.name.to_s == just_const_name
              comment = override_comment.source
              break
            end
          end

          # use any comments on this statement as a last resort
          if comment.nil? && statement.comments && statement.comments.source =~ /\S/
            comment = statement.comments.source
            stmt = statement.comments
          end

          # In the case of rb_define_const, the definition and comment are in
          # "/* definition: comment */" form.  The literal ':' and '\' characters
          # can be escaped with a backslash.
          if comment
            comment.scan(/\A\s*(.*?[^\s\\]):\s*(.+)/m) do |new_value, new_comment|
              object.value = new_value.gsub(/\\:/, ':')
              comment = new_comment
            end
            register_docstring(object, comment, stmt)
          end
        end

        def find_method_body(object, symbol)
          file = statement.file
          in_file = false
          if statement.comments && statement.comments.source =~ /\A\s*in (\S+)\Z/
            file = $1
            in_file = true
            process_file(file, object)
          end

          src_stmt = symbols[symbol]
          if src_stmt
            register_file_info(object, src_stmt.file, src_stmt.line, true)
            register_source(object, src_stmt)
            record_parameters(object, symbol, src_stmt)
            unless src_stmt.comments.nil? || src_stmt.comments.source.empty?
              register_docstring(object, src_stmt.comments.source, src_stmt)
              return # found docstring
            end
          end

          # found source (possibly) but no docstring
          # so look in overrides
          return if override_comments.any? do |name, override_comment|
            next unless override_comment.file == file
            name = name.gsub(/::([^:\.#]+?)\Z/, '.\1')

            # explicit namespace in override comment
            path = (name =~ /\.|#/ ? object.path : object.name.to_s)
            if path == name || path == name.sub(/new$/, 'initialize') || path == name.sub('.', '#')
              register_docstring(object, override_comment.source, override_comment)
              true
            else
              false
            end
          end

          # use any comments on this statement as a last resort
          if !in_file && statement.comments && statement.comments.source =~ /\S/
            register_docstring(object, statement.comments.source, statement)
          end
        end

        def record_parameters(object, symbol, src)
          # use regex to extract comma-delimited list of parameters from cfunc definition
          if src.source =~ /VALUE\s+#{symbol}\(([^)]*)\)\s*\{/m
            params = $~[1].split(/\s*,\s*/) # rubocop:disable Style/SpecialGlobalVars
            # cfunc for a "varargs" method has params "int argc, VALUE *argv"
            if params[0] =~ /int\s+argc/ && params[1] =~ /VALUE\s*\*\s*argv/
              object.parameters = [['*args', nil]]
            else
              # the first cfunc argument is the 'self' argument, we don't need that
              object.parameters = params.drop(1).map {|s| [s[/VALUE\s+(\S+)/, 1], nil] }
            end
          end
        end
      end
    end
  end
end
