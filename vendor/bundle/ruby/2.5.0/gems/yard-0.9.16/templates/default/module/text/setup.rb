# frozen_string_literal: true
def init
  sections :header, [T('docstring')], :children, :includes, :extends,
    :class_meths_list, :instance_meths_list
end

def class_meths
  @classmeths ||= method_listing.select {|o| o.scope == :class }
end

def instance_meths
  @instmeths ||= method_listing.select {|o| o.scope == :instance }
end
