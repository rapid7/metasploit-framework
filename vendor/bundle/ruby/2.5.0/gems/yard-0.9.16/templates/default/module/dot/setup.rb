# frozen_string_literal: true
def init
  @modules = object.children.select {|o| o.type == :module }
  @classes = object.children.select {|o| o.type == :class }
  sections :child, [:info], :classes, [T('class')], :header, [T('module')], :dependencies
end

def dependencies
  return unless options.dependencies
  erb(:dependencies)
end

def classes
  @classes.map {|k| yieldall :object => k }.join("\n")
end
