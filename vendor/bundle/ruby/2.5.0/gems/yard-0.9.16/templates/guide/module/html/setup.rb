# frozen_string_literal: true
include Helpers::ModuleHelper

def init
  sections :header, [T('docstring')], :method_list, [T('method')]
end

def method_list
  @meths = object.meths(:inherited => false, :included => false)
  cons = @meths.find(&:constructor?)
  @meths = @meths.reject {|meth| special_method?(meth) }
  @meths = sort_listing(prune_method_listing(@meths, false))
  @meths.unshift(cons) if cons
  erb(:method_list)
end

def sort_listing(list)
  list.sort_by {|o| [o.scope.to_s, o.name.to_s.downcase] }
end

def special_method?(meth)
  return true if meth.writer? && meth.attr_info[:read]
  return true if meth.name(true) == 'new'
  return true if meth.name(true) == '#method_missing'
  return true if meth.constructor?
  false
end
