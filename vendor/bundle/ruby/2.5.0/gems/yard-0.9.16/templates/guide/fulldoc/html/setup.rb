# frozen_string_literal: true
include T('default/fulldoc/html')

module OverrideFileLinks
  def resolve_links(text)
    result = ''
    log.enter_level(Logger::ERROR) { result = super }
    result
  end

  def url_for(object, *args)
    if CodeObjects::ExtraFileObject === object && object == options.readme
      'index.html'
    else
      super
    end
  end
end

Template.extra_includes << OverrideFileLinks

def init
  class << options.serializer
    define_method(:serialized_path) do |object|
      if CodeObjects::ExtraFileObject === object
        super(object).sub(/^file\./, '').downcase
      else
        super(object)
      end
    end
  end if options.serializer

  return serialize_onefile if options.onefile

  generate_assets
  options.delete(:objects)
  options.files.each {|file| serialize_file(file) }
  serialize_file(options.readme) if options.readme
end

def generate_assets
  %w(js/jquery.js js/app.js css/style.css css/common.css).each do |file|
    asset(file, file(file, true))
  end
end

def serialize_file(file)
  index = options.files.index(file)
  outfile = file.name.downcase + '.html'
  options.file = file
  if file.attributes[:namespace]
    options.object = Registry.at(file.attributes[:namespace])
  end
  options.object ||= Registry.root

  if file == options.readme
    serialize_index(options)
  else
    serialize_index(options) if !options.readme && index == 0
    Templates::Engine.with_serializer(outfile, options.serializer) do
      T('layout').run(options)
    end
  end
  options.delete(:file)
end

def serialize_onefile
  layout = Object.new.extend(T('layout'))
  options.css_data = layout.stylesheets.map {|sheet| file(sheet, true) }.join("\n")
  options.js_data = layout.javascripts.map {|script| file(script, true) }.join("")
  Templates::Engine.with_serializer('onefile.html', options.serializer) do
    T('onefile').run(options)
  end
end
