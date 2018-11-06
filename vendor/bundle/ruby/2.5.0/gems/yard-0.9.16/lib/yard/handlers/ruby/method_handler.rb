# frozen_string_literal: true
# Handles a method definition
class YARD::Handlers::Ruby::MethodHandler < YARD::Handlers::Ruby::Base
  handles :def, :defs

  process do
    meth = statement.method_name(true).to_s
    args = format_args
    blk = statement.block
    nobj = namespace
    mscope = scope
    if statement.type == :defs
      if statement[0][0].type == :ident
        raise YARD::Parser::UndocumentableError, 'method defined on object instance'
      end
      nobj = P(namespace, statement[0].source) if statement[0][0].type == :const
      mscope = :class
    end

    nobj = P(namespace, nobj.value) while nobj.type == :constant
    obj = register MethodObject.new(nobj, meth, mscope) do |o|
      o.signature = method_signature
      o.explicit = true
      o.parameters = args
    end

    # delete any aliases referencing old method
    nobj.aliases.each do |aobj, name|
      next unless name == obj.name
      nobj.aliases.delete(aobj)
    end if nobj.is_a?(NamespaceObject)

    if obj.constructor?
      unless obj.has_tag?(:return)
        obj.add_tag(YARD::Tags::Tag.new(:return,
          "a new instance of #{namespace.name}", namespace.name.to_s))
      end
    elsif mscope == :class && obj.docstring.blank? && %w(inherited included
        extended method_added method_removed method_undefined).include?(meth)
      obj.add_tag(YARD::Tags::Tag.new(:private, nil))
    elsif meth.to_s =~ /\?$/
      if obj.tag(:return) && (obj.tag(:return).types || []).empty?
        obj.tag(:return).types = ['Boolean']
      elsif obj.tag(:return).nil?
        unless obj.tags(:overload).any? {|overload| overload.tag(:return) }
          obj.add_tag(YARD::Tags::Tag.new(:return, "", "Boolean"))
        end
      end
    end

    if obj.has_tag?(:option)
      # create the options parameter if its missing
      obj.tags(:option).each do |option|
        expected_param = option.name
        unless obj.tags(:param).find {|x| x.name == expected_param }
          new_tag = YARD::Tags::Tag.new(:param, "a customizable set of options", "Hash", expected_param)
          obj.add_tag(new_tag)
        end
      end
    end

    info = obj.attr_info
    if info
      if meth.to_s =~ /=$/ # writer
        info[:write] = obj if info[:read]
      elsif info[:write]
        info[:read] = obj
      end
    end

    parse_block(blk, :owner => obj) # mainly for yield/exceptions
  end

  def format_args
    args = statement.parameters

    params = []

    if args.unnamed_required_params
      params += args.unnamed_required_params.map {|a| [a.source, nil] }
    end

    if args.unnamed_optional_params
      params += args.unnamed_optional_params.map do |a|
        [a[0].source, a[1].source]
      end
    end

    params << ['*' + args.splat_param.source, nil] if args.splat_param

    if args.unnamed_end_params
      params += args.unnamed_end_params.map {|a| [a.source, nil] }
    end

    if args.named_params
      params += args.named_params.map do |a|
        [a[0].source, a[1] ? a[1].source : nil]
      end
    end

    if args.double_splat_param
      params << ['**' + args.double_splat_param.source, nil]
    end

    params << ['&' + args.block_param.source, nil] if args.block_param

    params
  end

  def method_signature
    method_name = statement.method_name(true)
    if statement.parameters.any? {|e| e }
      "def #{method_name}(#{statement.parameters.source})"
    else
      "def #{method_name}"
    end
  end
end
