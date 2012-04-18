# -*- ruby encoding: utf-8 -*-

require 'cgi'

class Diff::LCS::HTMLDiff
  class << self
    attr_accessor :can_expand_tabs #:nodoc:
  end
  self.can_expand_tabs = true

  class Callbacks
    attr_accessor :output
    attr_accessor :match_class
    attr_accessor :only_a_class
    attr_accessor :only_b_class

    def initialize(output, options = {})
      @output = output
      options ||= {}

      @match_class = options[:match_class] || "match"
      @only_a_class = options[:only_a_class] || "only_a"
      @only_b_class = options[:only_b_class] || "only_b"
    end

    def htmlize(element, css_class)
      element = "&nbsp;" if element.empty?
      %Q|<pre class="#{__send__(css_class)}">#{element}</pre>\n|
    end
    private :htmlize

    # This will be called with both lines are the same
    def match(event)
      @output << htmlize(event.old_element, :match_class)
    end

    # This will be called when there is a line in A that isn't in B
    def discard_a(event)
      @output << htmlize(event.old_element, :only_a_class)
    end

    # This will be called when there is a line in B that isn't in A
    def discard_b(event)
      @output << htmlize(event.new_element, :only_b_class)
    end
  end

  DEFAULT_OPTIONS = {
    :expand_tabs => nil,
    :output => nil,
    :css => nil,
    :title => nil,
  }

  DEFAULT_CSS = <<-CSS
body { margin: 0; }
.diff
{
  border: 1px solid black;
  margin: 1em 2em;
}
p
{
  margin-left: 2em;
}
pre
{
  padding-left: 1em;
  margin: 0;
  font-family: Inconsolata, Consolas, Lucida, Courier, monospaced;
	white-space: pre;
}
.match { }
.only_a
{
  background-color: #fdd;
  color: red;
  text-decoration: line-through;
}
.only_b
{
  background-color: #ddf;
  color: blue;
  border-left: 3px solid blue
}
h1 { margin-left: 2em; }
  CSS

  def initialize(left, right, options = nil)
    @left     = left
    @right    = right
    @options  = options

    @options = DEFAULT_OPTIONS.dup if @options.nil?
  end

  def verify_options
    @options[:expand_tabs] ||= 4
    @options[:expand_tabs] = 4 if @options[:expand_tabs] < 0

    @options[:output] ||= $stdout

    @options[:css] ||= DEFAULT_CSS.dup

    @options[:title] ||= "diff"
  end
  private :verify_options

  attr_reader :options

  def run
    verify_options

    if @options[:expand_tabs] > 0 && self.class.can_expand_tabs
      formatter = Text::Format.new
      formatter.tabstop = @options[:expand_tabs]

      @left = left.map { |line| formatter.expand(line.chomp) }
      @right = right.map { |line| formatter.expand(line.chomp) }
    end

    @left.map! { |line| CGI.escapeHTML(line.chomp) }
    @right.map! { |line| CGI.escapeHTML(line.chomp) }

    @options[:output] << <<-OUTPUT
<html>
  <head>
    <title>#{@options[:title]}</title>
    <style type="text/css">
    #{@options[:css]}
    </style>
  </head>
  <body>
    <h1>#{@options[:title]}</h1>
    <p>Legend: <span class="only_a">Only in Old</span>&nbsp;
    <span class="only_b">Only in New</span></p>
    <div class="diff">
    OUTPUT

    callbacks = Callbacks.new(@options[:output])
    Diff::LCS.traverse_sequences(@left, @right, callbacks)

    @options[:output] << <<-OUTPUT
    </div>
  </body>
</html>
    OUTPUT
  end
end

# vim: ft=ruby
