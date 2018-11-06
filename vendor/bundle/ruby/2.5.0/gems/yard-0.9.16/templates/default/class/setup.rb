# frozen_string_literal: true
include T('default/module')

def init
  super
  sections.place(:subclasses).before(:children)
  sections.place(:constructor_details, [T('method_details')]).before(:methodmissing)
end

def constructor_details
  ctors = object.meths(:inherited => true, :included => true)
  @ctor = ctors.find(&:constructor?)
  return unless @ctor
  return if prune_method_listing([@ctor]).empty?
  erb(:constructor_details)
end

def subclasses
  return if object.path == "Object" # don't show subclasses for Object
  unless globals.subclasses
    globals.subclasses = {}
    list = run_verifier Registry.all(:class)
    list.each do |o|
      (globals.subclasses[o.superclass.path] ||= []) << o if o.superclass
    end
  end

  @subclasses = globals.subclasses[object.path]
  return if @subclasses.nil? || @subclasses.empty?
  @subclasses = @subclasses.sort_by(&:path).map do |child|
    name = child.path
    name = object.relative_path(child) if object.namespace
    [name, child]
  end
  erb(:subclasses)
end
