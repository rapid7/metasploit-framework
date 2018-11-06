# frozen_string_literal: true
def init
  return if object.docstring.blank? && !object.has_tag?(:api)
  sections :index, [:private, :deprecated, :abstract, :todo, :note, :returns_void, :text], T('tags')
end

def private
  return unless object.has_tag?(:api) && object.tag(:api).text == 'private'
  erb(:private)
end

def abstract
  return unless object.has_tag?(:abstract)
  erb(:abstract)
end

def deprecated
  return unless object.has_tag?(:deprecated)
  erb(:deprecated)
end

def todo
  return unless object.has_tag?(:todo)
  erb(:todo)
end

def note
  return unless object.has_tag?(:note)
  erb(:note)
end

def returns_void
  return unless object.type == :method
  return if object.name == :initialize && object.scope == :instance
  return unless object.tags(:return).size == 1 && object.tag(:return).types == ['void']
  erb(:returns_void)
end

def docstring_text
  text = ""
  unless object.tags(:overload).size == 1 && object.docstring.empty?
    text = object.docstring
  end

  if text.strip.empty? && object.tags(:return).size == 1 && object.tag(:return).text
    text = object.tag(:return).text.gsub(/\A([a-z])/, &:downcase)
    text = "Returns #{text}" unless text.empty? || text =~ /^\s*return/i
    text = text.gsub(/\A([a-z])/, &:upcase)
  end

  text.strip
end
