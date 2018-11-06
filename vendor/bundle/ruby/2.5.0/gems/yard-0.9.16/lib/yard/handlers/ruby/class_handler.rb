# frozen_string_literal: true
# Handles class declarations
class YARD::Handlers::Ruby::ClassHandler < YARD::Handlers::Ruby::Base
  include YARD::Handlers::Ruby::StructHandlerMethods
  handles :class, :sclass
  namespace_only

  process do
    classname = statement[0].source.gsub(/\s/, '')
    if statement.type == :class
      superclass = parse_superclass(statement[1])
      if superclass == "Struct"
        is_a_struct = true
        superclass = struct_superclass_name(statement[1]) # refine the superclass if possible
        create_struct_superclass(superclass, statement[1])
      end
      undocsuper = statement[1] && superclass.nil?
      klass = register ClassObject.new(namespace, classname) do |o|
        o.superclass = superclass if superclass
        o.superclass.type = :class if o.superclass.is_a?(Proxy)
      end
      if is_a_struct
        parse_struct_superclass(klass, statement[1])
      elsif klass
        create_attributes(klass, members_from_tags(klass))
      end
      parse_block(statement[2], :namespace => klass)

      if undocsuper
        raise YARD::Parser::UndocumentableError, 'superclass (class was added without superclass)'
      end
    elsif statement.type == :sclass
      if statement[0] == s(:var_ref, s(:kw, "self"))
        parse_block(statement[1], :namespace => namespace, :scope => :class)
      else
        proxy = Proxy.new(namespace, classname)

        # Allow constants to reference class names
        if ConstantObject === proxy
          if proxy.value =~ /\A#{NAMESPACEMATCH}\Z/
            proxy = Proxy.new(namespace, proxy.value)
          else
            raise YARD::Parser::UndocumentableError, "constant class reference '#{classname}'"
          end
        end

        if classname[0, 1] =~ /[A-Z]/
          register ClassObject.new(namespace, classname) if Proxy === proxy
          parse_block(statement[1], :namespace => proxy, :scope => :class)
        else
          raise YARD::Parser::UndocumentableError, "class '#{classname}'"
        end
      end
    else
      sig_end = (statement[1] ? statement[1].source_end : statement[0].source_end) - statement.source_start
      raise YARD::Parser::UndocumentableError, "class: #{statement.source[0..sig_end]}"
    end
  end

  private

  # Extract the parameters from the Struct.new AST node, returning them as a list
  # of strings
  #
  # @param [MethodCallNode] superclass the AST node for the Struct.new call
  # @return [Array<String>] the member names to generate methods for
  def extract_parameters(superclass)
    members = superclass.parameters.select {|x| x && x.type == :symbol_literal }
    members.map! {|x| x.source.strip[1..-1] }
    members
  end

  def create_struct_superclass(superclass, superclass_def)
    return if superclass == "Struct"
    the_super = register ClassObject.new(P("Struct"), superclass[8..-1]) do |o|
      o.superclass = "Struct"
    end
    parse_struct_superclass(the_super, superclass_def)
    the_super
  end

  def struct_superclass_name(superclass)
    if superclass.call?
      first = superclass.parameters.first
      if first.type == :string_literal && first[0].type == :string_content && first[0].size == 1
        return "Struct::#{first[0][0][0]}"
      end
    end
    "Struct"
  end

  def parse_struct_superclass(klass, superclass)
    return unless superclass.call? && superclass.parameters
    members = extract_parameters(superclass)
    create_attributes(klass, members)
  end

  def parse_superclass(superclass)
    return nil unless superclass

    case superclass.type
    when :var_ref
      return namespace.path if superclass.first == s(:kw, "self")
      return superclass.source if superclass.first.type == :const
    when :const, :const_ref, :const_path_ref, :top_const_ref
      return superclass.source
    when :fcall, :command
      methname = superclass.method_name.source
      return superclass.parameters.first.source if methname == "DelegateClass"
      return methname if superclass.method_name.type == :const
    when :call, :command_call
      cname = superclass.namespace.source
      if cname =~ /^O?Struct$/ && superclass.method_name(true) == :new
        return cname
      end
    end
    nil
  end
end
