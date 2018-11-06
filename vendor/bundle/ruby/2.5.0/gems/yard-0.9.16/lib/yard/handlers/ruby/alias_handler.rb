# frozen_string_literal: true
# Handles alias and alias_method calls
class YARD::Handlers::Ruby::AliasHandler < YARD::Handlers::Ruby::Base
  handles :alias, method_call(:alias_method)
  namespace_only

  process do
    names = []
    if statement.type == :alias
      names = statement.map {|o| o.jump(:ident, :op, :kw, :const).source }
    elsif statement.call?
      statement.parameters(false).each do |obj|
        case obj.type
        when :symbol_literal, :dyna_symbol
          names << obj.jump(:ident, :op, :kw, :const).source
        when :string_literal
          names << obj.jump(:string_content).source
        end
      end
    end
    raise YARD::Parser::UndocumentableError, "alias/alias_method" if names.size != 2

    new_meth = names[0].to_sym
    old_meth = names[1].to_sym
    old_obj = namespace.child(:name => old_meth, :scope => scope)
    new_obj = register MethodObject.new(namespace, new_meth, scope) do |o|
      o.add_file(parser.file, statement.line)
    end
    namespace.aliases[new_obj] = old_meth

    if old_obj
      new_obj.signature = old_obj.signature
      new_obj.source = old_obj.source
      comments = [old_obj.docstring.to_raw, statement.comments].join("\n")
      doc = YARD::Docstring.parser.parse(comments, new_obj, self)
      new_obj.docstring = doc.to_docstring
      new_obj.docstring.line_range = statement.comments_range
      new_obj.docstring.hash_flag = statement.comments_hash_flag
      new_obj.docstring.object = new_obj
    else
      new_obj.signature = "def #{new_meth}" # this is all we know.
    end
  end
end
