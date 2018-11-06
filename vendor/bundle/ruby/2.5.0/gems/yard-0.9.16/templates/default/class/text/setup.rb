# frozen_string_literal: true
include T('default/module/text')

def init
  super
  sections.place(:subclasses).before(:children)
  sections.delete(:children)
end

def format_object_title(object)
  "Class: #{object.title} < #{object.superclass.title}"
end
