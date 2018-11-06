# frozen_string_literal: true
# (see Ruby::AttributeHandler)
class YARD::Handlers::Ruby::Legacy::AttributeHandler < YARD::Handlers::Ruby::Legacy::Base
  handles(/\Aattr(?:_(?:reader|writer|accessor))?(?:\s|\()/)
  namespace_only

  process do
    begin
      attr_type   = statement.tokens.first.text.to_sym
      symbols     = tokval_list statement.tokens[2..-1], :attr, TkTRUE, TkFALSE
      read = true
      write = false
    rescue SyntaxError
      raise YARD::Parser::UndocumentableError, attr_type
    end

    # Change read/write based on attr_reader/writer/accessor
    case attr_type
    when :attr
      # In the case of 'attr', the second parameter (if given) isn't a symbol.
      write = symbols.pop if symbols.size == 2
    when :attr_accessor
      write = true
    when :attr_reader
      # change nothing
    when :attr_writer
      read = false
      write = true
    end

    # Add all attributes
    symbols.each do |name|
      namespace.attributes[scope][name] = SymbolHash[:read => nil, :write => nil]

      # Show their methods as well
      {:read => name, :write => "#{name}="}.each do |type, meth|
        if type == :read ? read : write
          o = MethodObject.new(namespace, meth, scope)
          if type == :write
            o.parameters = [['value', nil]]
            src = "def #{meth}(value)"
            full_src = "#{src}\n  @#{name} = value\nend"
            doc = "Sets the attribute #{name}\n@param value the value to set the attribute #{name} to."
          else
            src = "def #{meth}"
            full_src = "#{src}\n  @#{name}\nend"
            doc = "Returns the value of attribute #{name}"
          end
          o.source ||= full_src
          o.signature ||= src
          register(o)
          o.docstring = doc if o.docstring.blank?(false)

          # Regsiter the object explicitly
          namespace.attributes[scope][name][type] = o
        else
          obj = namespace.children.find {|other| other.name == meth.to_sym && other.scope == scope }

          # register an existing method as attribute
          namespace.attributes[scope][name][type] = obj if obj
        end
      end
    end
  end
end
