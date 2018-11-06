# frozen_string_literal: true
include Helpers::ModuleHelper

def init
  sections :header, :box_info, :pre_docstring, T('docstring'), :children,
    :constant_summary, [T('docstring')], :inherited_constants,
    :attribute_summary, [:item_summary], :inherited_attributes,
    :method_summary, [:item_summary], :inherited_methods,
    :methodmissing, [T('method_details')],
    :attribute_details, [T('method_details')],
    :method_details_list, [T('method_details')]
end

def pre_docstring
  return if object.docstring.blank?
  erb(:pre_docstring)
end

def children
  @inner = [[:modules, []], [:classes, []]]
  object.children.each do |child|
    @inner[0][1] << child if child.type == :module
    @inner[1][1] << child if child.type == :class
  end
  @inner.map! {|v| [v[0], run_verifier(v[1].sort_by {|o| o.name.to_s })] }
  return if (@inner[0][1].size + @inner[1][1].size) == 0
  erb(:children)
end

def methodmissing
  mms = object.meths(:inherited => true, :included => true)
  @mm = mms.find {|o| o.name == :method_missing && o.scope == :instance }
  erb(:methodmissing) if @mm
end

def method_listing(include_specials = true)
  return @smeths ||= method_listing.reject {|o| special_method?(o) } unless include_specials
  return @meths if defined?(@meths) && @meths
  @meths = object.meths(:inherited => false, :included => !options.embed_mixins.empty?)
  unless options.embed_mixins.empty?
    @meths = @meths.reject {|m| options.embed_mixins_match?(m.namespace) == false }
  end
  @meths = sort_listing(prune_method_listing(@meths))
  @meths
end

def special_method?(meth)
  return true if meth.name(true) == '#method_missing'
  return true if meth.constructor?
  false
end

def attr_listing
  return @attrs if defined?(@attrs) && @attrs
  @attrs = []
  object.inheritance_tree(true).each do |superclass|
    next if superclass.is_a?(CodeObjects::Proxy)
    next if !options.embed_mixins.empty? &&
            !options.embed_mixins_match?(superclass)
    [:class, :instance].each do |scope|
      superclass.attributes[scope].each do |_name, rw|
        attr = prune_method_listing([rw[:read], rw[:write]].compact, false).first
        @attrs << attr if attr
      end
    end
    break if options.embed_mixins.empty?
  end
  @attrs = sort_listing(@attrs)
end

def constant_listing
  return @constants if defined?(@constants) && @constants
  @constants = object.constants(:included => false, :inherited => false)
  @constants += object.cvars
  @constants = run_verifier(@constants)
  @constants
end

def sort_listing(list)
  list.sort_by {|o| [o.scope.to_s, o.name.to_s.downcase] }
end

def inherited_attr_list
  object.inheritance_tree(true)[1..-1].each do |superclass|
    next if superclass.is_a?(YARD::CodeObjects::Proxy)
    next if !options.embed_mixins.empty? && options.embed_mixins_match?(superclass) != false
    attribs = superclass.attributes[:instance]
    attribs = attribs.select {|name, _rw| object.child(:scope => :instance, :name => name).nil? }
    attribs = attribs.sort_by {|args| args.first.to_s }.map {|_n, m| m[:read] || m[:write] }
    attribs = prune_method_listing(attribs, false)
    yield superclass, attribs unless attribs.empty?
  end
end

def inherited_constant_list
  object.inheritance_tree(true)[1..-1].each do |superclass|
    next if superclass.is_a?(YARD::CodeObjects::Proxy)
    next if !options.embed_mixins.empty? && options.embed_mixins_match?(superclass) != false
    consts = superclass.constants(:included => false, :inherited => false)
    consts = consts.select {|const| object.child(:type => :constant, :name => const.name).nil? }
    consts = consts.sort_by {|const| const.name.to_s }
    consts = run_verifier(consts)
    yield superclass, consts unless consts.empty?
  end
end

def docstring_full(obj)
  docstring = obj.tags(:overload).size == 1 && obj.docstring.empty? ?
    obj.tag(:overload).docstring : obj.docstring

  if docstring.summary.empty? && obj.tags(:return).size == 1 && obj.tag(:return).text
    docstring = Docstring.new(obj.tag(:return).text.gsub(/\A([a-z])/, &:upcase).strip)
  end

  docstring
end

def docstring_summary(obj)
  docstring_full(obj).summary
end

def groups(list, type = "Method")
  groups_data = object.groups
  if groups_data
    list.each {|m| groups_data |= [m.group] if m.group && owner != m.namespace }
    others = list.select {|m| !m.group || !groups_data.include?(m.group) }
    groups_data.each do |name|
      items = list.select {|m| m.group == name }
      yield(items, name) unless items.empty?
    end
  else
    others = []
    group_data = {}
    list.each do |itm|
      if itm.group
        (group_data[itm.group] ||= []) << itm
      else
        others << itm
      end
    end
    group_data.each {|group, items| yield(items, group) unless items.empty? }
  end

  return if others.empty?
  if others.first.respond_to?(:scope)
    scopes(others) {|items, scope| yield(items, "#{scope.to_s.capitalize} #{type} Summary") }
  else
    yield(others, "#{type} Summary")
  end
end

def scopes(list)
  [:class, :instance].each do |scope|
    items = list.select {|m| m.scope == scope }
    yield(items, scope) unless items.empty?
  end
end

def mixed_into(object)
  unless globals.mixed_into
    globals.mixed_into = {}
    list = run_verifier Registry.all(:class, :module)
    list.each {|o| o.mixins.each {|m| (globals.mixed_into[m.path] ||= []) << o } }
  end

  globals.mixed_into[object.path] || []
end
