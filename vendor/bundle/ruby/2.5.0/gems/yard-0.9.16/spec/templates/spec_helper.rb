# frozen_string_literal: true

include YARD::Templates

def only_copy?(result, example, type)
  return false unless defined?($COPY)

  if $COPY == :all || $COPY == example
    puts(result) unless $COPYT && $COPYT != type
  end
  $COPY ? true : false
end

def text_equals(result, expected_example)
  return if only_copy?(result, expected_example, :text)
  text_equals_string(result, example_contents(expected_example, :txt))
end

def text_equals_string(result, expected)
  expect(result).to eq expected
end

def html_equals(result, expected_example)
  return if only_copy?(result, expected_example, :html)
  html_equals_string(result, example_contents(expected_example))
end

def html_equals_string(result, expected)
  result = String.new(result)
  expected = String.new(expected)
  [expected, result].each do |value|
    value.gsub!(/(>)\s+|\s+(<)/, '\1\2')
    value.gsub!(/&#39;/, "'")
    value.strip!
  end
  text_equals_string(result, expected)
end

def example_contents(filename, ext = 'html')
  File.read(File.join(File.dirname(__FILE__), 'examples', "#{filename}.#{ext}"))
end

module YARD::Templates::Engine
  class << self
    public :find_template_paths
  end
end

class TestHtmlTemplateOptions < Templates::TemplateOptions
  default_attr :markup, :none
  default_attr :default_return, ""
  default_attr :format, :html
  default_attr :highlight, false
end

class TestTextTemplateOptions < Templates::TemplateOptions
  default_attr :markup, :none
  default_attr :default_return, ""
  default_attr :format, :text
  default_attr :highlight, false
end

def html_options(opts = {})
  template_options(opts, TestHtmlTemplateOptions)
end

def text_options(opts = {})
  template_options(opts, TestTextTemplateOptions)
end

def template_options(opts, klass)
  options = klass.new
  options.reset_defaults
  options.update(opts)
  options
end
