# frozen_string_literal: true
include T('default/layout/html')
include YARD::Parser::Ruby::Legacy

def init
  override_serializer
  @object = YARD::Registry.root
  @files.shift
  @objects.delete(YARD::Registry.root)
  @objects.unshift(YARD::Registry.root)
  sections :layout, [:readme, :files, :all_objects]
end

def all_objects
  @objects.map {|obj| obj.format(options) }.join("\n")
end

def layout
  layout = Object.new.extend(T('layout'))
  @css_data = layout.stylesheets.map {|sheet| read_asset(sheet) }.join("\n")
  @js_data = layout.javascripts.map {|script| read_asset(script) }.join("")

  erb(:layout)
end

def read_asset(file)
  file = T('fulldoc').find_file(file)
  return unless file
  data = File.read(file)
  superfile = self.class.find_nth_file('fulldoc', 2)
  data.gsub!('{{{__super__}}}', superfile ? IO.read(superfile) : "")
  data
end

private

def parse_top_comments_from_file
  return unless defined?(@readme) && @readme
  return @readme.contents unless @readme.filename =~ /\.rb$/
  data = ""
  tokens = TokenList.new(@readme.contents)
  tokens.each do |token|
    break unless token.is_a?(RubyToken::TkCOMMENT) || token.is_a?(RubyToken::TkNL)
    data << (token.text[/\A#\s{0,1}(.*)/, 1] || "\n")
  end
  YARD::Docstring.new(data)
end

def override_serializer
  return if @serializer.nil?
  class << @serializer
    define_method(:serialize) do |object, data|
      return unless object == 'index.html'
      super(object, data)
    end

    define_method(:serialized_path) do |object|
      return object if object.is_a?(String)
      'index.html'
    end
  end
end
