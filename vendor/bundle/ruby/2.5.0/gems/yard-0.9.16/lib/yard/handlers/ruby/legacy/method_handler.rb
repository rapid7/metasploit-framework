# frozen_string_literal: true
# (see Ruby::MethodHandler)
class YARD::Handlers::Ruby::Legacy::MethodHandler < YARD::Handlers::Ruby::Legacy::Base
  handles TkDEF

  process do
    nobj = namespace
    mscope = scope

    if statement.tokens.to_s =~ /^def\s+(#{METHODMATCH})(?:(?:\s+|\s*\()(.*)(?:\)\s*$)?)?/m
      meth = $1
      args = $2
      meth.gsub!(/\s+/, '')
      args = tokval_list(YARD::Parser::Ruby::Legacy::TokenList.new(args), :all)
      args.map! do |a|
        k, v, r = *a.split(/(:)|=/, 2)
        if r
          k += v
          v = r
        end
        [k.strip, (v ? v.strip : nil)]
      end if args
    else
      raise YARD::Parser::UndocumentableError, "method: invalid name"
    end

    # Class method if prefixed by self(::|.) or Module(::|.)
    if meth =~ /(?:#{NSEPQ}|#{CSEPQ})([^#{NSEP}#{CSEPQ}]+)$/
      mscope = :class
      meth = $1
      prefix = $`
      if prefix =~ /^[a-z]/ && prefix != "self"
        raise YARD::Parser::UndocumentableError, 'method defined on object instance'
      end
      nobj = P(namespace, prefix) unless prefix == "self"
    end

    nobj = P(namespace, nobj.value) while nobj.type == :constant
    obj = register MethodObject.new(nobj, meth, mscope) do |o|
      o.explicit = true
      o.parameters = args
    end

    # delete any aliases referencing old method
    nobj.aliases.each do |aobj, name|
      next unless name == obj.name
      nobj.aliases.delete(aobj)
    end if nobj.is_a?(NamespaceObject)

    if mscope == :instance && meth == "initialize"
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

    parse_block(:owner => obj) # mainly for yield/exceptions
  end
end
