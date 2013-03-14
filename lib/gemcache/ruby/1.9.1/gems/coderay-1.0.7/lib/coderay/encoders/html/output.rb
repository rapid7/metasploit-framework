module CodeRay
module Encoders

  class HTML

    # This module is included in the output String of the HTML Encoder.
    #
    # It provides methods like wrap, div, page etc.
    #
    # Remember to use #clone instead of #dup to keep the modules the object was
    # extended with.
    #
    # TODO: Rewrite this without monkey patching.
    module Output

      attr_accessor :css

      class << self

        # Raises an exception if an object that doesn't respond to to_str is extended by Output,
        # to prevent users from misuse. Use Module#remove_method to disable.
        def extended o  # :nodoc:
          warn "The Output module is intended to extend instances of String, not #{o.class}." unless o.respond_to? :to_str
        end

        def make_stylesheet css, in_tag = false  # :nodoc:
          sheet = css.stylesheet
          sheet = <<-'CSS' if in_tag
<style type="text/css">
#{sheet}
</style>
          CSS
          sheet
        end

        def page_template_for_css css  # :nodoc:
          sheet = make_stylesheet css
          PAGE.apply 'CSS', sheet
        end

      end

      def wrapped_in? element
        wrapped_in == element
      end

      def wrapped_in
        @wrapped_in ||= nil
      end
      attr_writer :wrapped_in

      def wrap_in! template
        Template.wrap! self, template, 'CONTENT'
        self
      end
      
      def apply_title! title
        self.sub!(/(<title>)(<\/title>)/) { $1 + title + $2 }
        self
      end

      def wrap! element, *args
        return self if not element or element == wrapped_in
        case element
        when :div
          raise "Can't wrap %p in %p" % [wrapped_in, element] unless wrapped_in? nil
          wrap_in! DIV
        when :span
          raise "Can't wrap %p in %p" % [wrapped_in, element] unless wrapped_in? nil
          wrap_in! SPAN
        when :page
          wrap! :div if wrapped_in? nil
          raise "Can't wrap %p in %p" % [wrapped_in, element] unless wrapped_in? :div
          wrap_in! Output.page_template_for_css(@css)
          if args.first.is_a?(Hash) && title = args.first[:title]
            apply_title! title
          end
          self
        when nil
          return self
        else
          raise "Unknown value %p for :wrap" % element
        end
        @wrapped_in = element
        self
      end

      def stylesheet in_tag = false
        Output.make_stylesheet @css, in_tag
      end

#-- don't include the templates in docu

      class Template < String  # :nodoc:

        def self.wrap! str, template, target
          target = Regexp.new(Regexp.escape("<%#{target}%>"))
          if template =~ target
            str[0,0] = $`
            str << $'
          else
            raise "Template target <%%%p%%> not found" % target
          end
        end

        def apply target, replacement
          target = Regexp.new(Regexp.escape("<%#{target}%>"))
          if self =~ target
            Template.new($` + replacement + $')
          else
            raise "Template target <%%%p%%> not found" % target
          end
        end

      end

      SPAN = Template.new '<span class="CodeRay"><%CONTENT%></span>'

      DIV = Template.new <<-DIV
<div class="CodeRay">
  <div class="code"><pre><%CONTENT%></pre></div>
</div>
      DIV

      TABLE = Template.new <<-TABLE
<table class="CodeRay"><tr>
  <td class="line-numbers" title="double click to toggle" ondblclick="with (this.firstChild.style) { display = (display == '') ? 'none' : '' }"><pre><%LINE_NUMBERS%></pre></td>
  <td class="code"><pre><%CONTENT%></pre></td>
</tr></table>
      TABLE

      PAGE = Template.new <<-PAGE
<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
  <title></title>
  <style type="text/css">
.CodeRay .line-numbers a {
  text-decoration: inherit;
  color: inherit;
}
body {
  background-color: white;
  padding: 0;
  margin: 0;
}
<%CSS%>
.CodeRay {
  border: none;
}
  </style>
</head>
<body>

<%CONTENT%>
</body>
</html>
      PAGE

    end

  end

end
end
