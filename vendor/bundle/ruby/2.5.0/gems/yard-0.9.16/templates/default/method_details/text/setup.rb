# frozen_string_literal: true
def init
  super
  sections.last.pop
end

def format_object_title(object)
  title = "Method: #{object.name(true)}"
  title += " (#{object.namespace})" unless object.namespace.root?
  title
end
