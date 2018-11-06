# frozen_string_literal: true
require 'cgi'

module YARD
  module Templates::Helpers
    # The helper module for HTML templates.
    module HtmlHelper
      include MarkupHelper
      include HtmlSyntaxHighlightHelper

      # @private
      URLMATCH = /[^\w\s~!\*'\(\):;@&=\$,\[\]<>-]/

      # @group Escaping Template Data

      # Escapes HTML entities
      #
      # @param [String] text the text to escape
      # @return [String] the HTML with escaped entities
      def h(text)
        CGI.escapeHTML(text.to_s)
      end

      # Escapes a URL
      #
      # @param [String] text the URL
      # @return [String] the escaped URL
      def urlencode(text)
        text = text.dup
        enc = nil
        if text.respond_to?(:force_encoding)
          enc = text.encoding
          text = text.force_encoding('binary')
        end

        text = text.gsub(/%[a-z0-9]{2}|#{URLMATCH}/i) do
          $&.size > 1 ? $& : "%" + $&.ord.to_s(16).upcase
        end.tr(' ', '+')

        text = text.force_encoding(enc) if enc
        text
      end

      module_function :urlencode

      # @group Converting Markup to HTML

      # Turns text into HTML using +markup+ style formatting.
      #
      # @param [String] text the text to format
      # @param [Symbol] markup examples are +:markdown+, +:textile+, +:rdoc+.
      #   To add a custom markup type, see {MarkupHelper}
      # @return [String] the HTML
      def htmlify(text, markup = options.markup)
        markup_meth = "html_markup_#{markup}"
        return text unless respond_to?(markup_meth)
        return "" unless text
        return text unless markup
        html = send(markup_meth, text).dup
        if html.respond_to?(:encode)
          html = html.force_encoding(text.encoding) # for libs that mess with encoding
          html = html.encode(:invalid => :replace, :replace => '?')
        end
        html = resolve_links(html)
        unless [:text, :none, :pre].include?(markup)
          html = parse_codeblocks(html)
        end
        html
      end

      # Converts Markdown to HTML
      # @param [String] text input Markdown text
      # @return [String] output HTML
      # @since 0.6.0
      def html_markup_markdown(text)
        # TODO: other libraries might be more complex
        provider = markup_class(:markdown)
        if provider.to_s == 'RDiscount'
          provider.new(text, :autolink).to_html
        elsif provider.to_s == 'RedcarpetCompat'
          provider.new(text, :no_intraemphasis, :gh_blockcode,
                             :fenced_code, :autolink, :tables,
                             :lax_spacing).to_html
        else
          provider.new(text).to_html
        end
      end

      # Converts org-mode to HTML
      # @param [String] text input org-mode text
      # @return [String] output HTML
      def html_markup_org(text)
        markup_class(:org).new(text).to_html
      end

      # Converts Asciidoc to HTML
      # @param [String] text input Asciidoc text
      # @return [String] output HTML
      def html_markup_asciidoc(text)
        markup_class(:asciidoc).render(text)
      end

      # Converts Textile to HTML
      # @param [String] text the input Textile text
      # @return [String] output HTML
      # @since 0.6.0
      def html_markup_textile(text)
        doc = markup_class(:textile).new(text)
        doc.hard_breaks = false if doc.respond_to?(:hard_breaks=)
        doc.to_html
      end

      # Converts plaintext to strict Textile (hard breaks)
      # @param [String] text the input textile data
      # @return [String] the output HTML
      # @since 0.6.0
      def html_markup_textile_strict(text)
        markup_class(:textile).new(text).to_html
      end

      # Converts RDoc formatting (SimpleMarkup) to HTML
      # @param [String] text the input RDoc formatted text
      # @return [String] output HTML
      # @since 0.6.0
      def html_markup_rdoc(text)
        doc = markup_class(:rdoc).new(text)
        doc.from_path = url_for(object) if doc.respond_to?(:from_path=)
        doc.to_html
      end

      # Converts plaintext to pre-formatted HTML
      # @param [String] text the input text
      # @return [String] the output HTML
      # @since 0.6.0
      def html_markup_pre(text)
        "<pre>" + h(text) + "</pre>"
      end

      # Converts plaintext to regular HTML
      # @param [String] text the input text
      # @return [String] the output HTML
      # @since 0.6.0
      def html_markup_text(text)
        h(text).gsub(/\r?\n/, '<br/>')
      end

      # @return [String] the same text with no markup
      # @since 0.6.6
      def html_markup_none(text)
        h(text)
      end

      # Converts HTML to HTML
      # @param [String] text input html
      # @return [String] output HTML
      # @since 0.6.0
      def html_markup_html(text)
        text
      end

      # Highlights Ruby source. Similar to {#html_syntax_highlight}, but
      # this method is meant to be called from {#htmlify} when markup is
      # set to "ruby".
      #
      # @param [String] source the Ruby source
      # @return [String] the highlighted HTML
      # @since 0.7.0
      def html_markup_ruby(source)
        '<pre class="code ruby">' + html_syntax_highlight(source, :ruby) + '</pre>'
      end

      # @return [String] HTMLified text as a single line (paragraphs removed)
      def htmlify_line(*args)
        "<div class='inline'>" + htmlify(*args) + "</div>"
      end

      # @group Syntax Highlighting Source Code

      # Syntax highlights +source+ in language +type+.
      #
      # @note To support a specific language +type+, implement the method
      #   +html_syntax_highlight_TYPE+ in this class.
      #
      # @param [String] source the source code to highlight
      # @param [Symbol, String] type the language type (:ruby, :plain, etc). Use
      #   :plain for no syntax highlighting.
      # @return [String] the highlighted source
      def html_syntax_highlight(source, type = nil)
        return "" unless source
        return h(source) unless options.highlight

        new_type, source = parse_lang_for_codeblock(source)
        type ||= new_type || :ruby
        meth = "html_syntax_highlight_#{type}"
        respond_to?(meth) ? send(meth, source) : h(source)
      end

      # @return [String] unhighlighted source
      def html_syntax_highlight_plain(source)
        h(source)
      end

      # @group Linking Objects and URLs

      # Resolves any text in the form of +{Name}+ to the object specified by
      # Name. Also supports link titles in the form +{Name title}+.
      #
      # @example Linking to an instance method
      #   resolve_links("{MyClass#method}") # => "<a href='...'>MyClass#method</a>"
      # @example Linking to a class with a title
      #   resolve_links("{A::B::C the C class}") # => "<a href='...'>the c class</a>"
      # @param [String] text the text to resolve links in
      # @return [String] HTML with linkified references
      def resolve_links(text)
        code_tags = 0
        text.gsub(%r{<(/)?(pre|code|tt)|(\\|!)?\{(?!\})(\S+?)(?:\s([^\}]*?\S))?\}(?=[\W<]|.+</|$)}m) do |str|
          closed = $1
          tag = $2
          escape = $3
          name = $4
          title = $5
          match = $&
          if tag
            code_tags += (closed ? -1 : 1)
            next str
          end
          next str unless code_tags == 0

          next(match[1..-1]) if escape

          next(match) if name[0, 1] == '|'

          if name == '<a' && title =~ %r{href=["'](.+?)["'].*>.*</a>\s*(.*)\Z}
            name = $1
            title = $2
            title = nil if title.empty?
          end

          name = CGI.unescapeHTML(name)

          if object.is_a?(String)
            object
          else
            link = linkify(name, title)
            if (link == name || link == title) && (name + ' ' + link !~ /\A<a\s.*>/)
              match = /(.+)?(\{#{Regexp.quote name}(?:\s.*?)?\})(.+)?/.match(text)
              file = (defined?(@file) && @file ? @file.filename : object.file) || '(unknown)'
              line = (defined?(@file) && @file ? 1 : (object.docstring.line_range ? object.docstring.line_range.first : 1)) + (match ? $`.count("\n") : 0)
              log.warn "In file `#{file}':#{line}: Cannot resolve link to #{name} from text" + (match ? ":" : ".") +
                       "\n\t" + (match[1] ? '...' : '') + match[2].delete("\n") + (match[3] ? '...' : '') if match
            end

            link
          end
        end
      end

      # (see BaseHelper#link_file)
      def link_file(filename, title = nil, anchor = nil)
        if CodeObjects::ExtraFileObject === filename
          file = filename
        else
          contents = File.file?(filename) ? nil : ''
          file = CodeObjects::ExtraFileObject.new(filename, contents)
        end
        return title || file.title unless serializer
        link_url(url_for_file(file, anchor), title || file.title)
      end

      # (see BaseHelper#link_include_file)
      def link_include_file(file)
        unless file.is_a?(CodeObjects::ExtraFileObject)
          file = CodeObjects::ExtraFileObject.new(file)
        end
        file.attributes[:markup] ||= markup_for_file('', file.filename)
        insert_include(file.contents, file.attributes[:markup] || options.markup)
      end

      # (see BaseHelper#link_include_object)
      def link_include_object(obj)
        insert_include(obj.docstring)
      end

      # Inserts an include link while respecting inlining
      def insert_include(text, markup = options.markup)
        htmlify(text, markup).gsub(%r{\A\s*<p>|</p>\s*\Z}, '')
      end

      # (see BaseHelper#link_object)
      def link_object(obj, title = nil, anchor = nil, relative = true)
        return title if obj.nil?
        obj = Registry.resolve(object, obj, true, true) if obj.is_a?(String)
        if title
          title = title.to_s
        elsif object.is_a?(CodeObjects::Base)
          # Check if we're linking to a class method in the current
          # object. If we are, create a title in the format of
          # "CurrentClass.method_name"
          if obj.is_a?(CodeObjects::MethodObject) && obj.scope == :class && obj.parent == object
            title = h([object.name, obj.sep, obj.name].join)
          elsif obj.title != obj.path
            title = h(obj.title)
          else
            title = h(object.relative_path(obj))
          end
        else
          title = h(obj.title)
        end
        return title unless serializer
        return title if obj.is_a?(CodeObjects::Proxy)

        link = url_for(obj, anchor, relative)
        link = link ? link_url(link, title, :title => h("#{obj.title} (#{obj.type})")) : title
        "<span class='object_link'>" + link + "</span>"
      end

      # (see BaseHelper#link_url)
      def link_url(url, title = nil, params = {})
        title ||= url
        title = title.gsub(/[\r\n]/, ' ')
        params = SymbolHash.new(false).update(
          :href => url,
          :title => h(title)
        ).update(params)
        params[:target] ||= '_parent' if url =~ %r{^(\w+)://}
        "<a #{tag_attrs(params)}>#{title}</a>".gsub(/[\r\n]/, ' ')
      end

      # @group URL Helpers

      # @param [CodeObjects::Base] object the object to get an anchor for
      # @return [String] the anchor for a specific object
      def anchor_for(object)
        case object
        when CodeObjects::MethodObject
          "#{object.name}-#{object.scope}_#{object.type}"
        when CodeObjects::ClassVariableObject
          "#{object.name.to_s.gsub('@@', '')}-#{object.type}"
        when CodeObjects::Base
          "#{object.name}-#{object.type}"
        when CodeObjects::Proxy
          object.path
        else
          object.to_s
        end
      end

      # Returns the URL for an object.
      #
      # @param [String, CodeObjects::Base] obj the object (or object path) to link to
      # @param [String] anchor the anchor to link to
      # @param [Boolean] relative use a relative or absolute link
      # @return [String] the URL location of the object
      def url_for(obj, anchor = nil, relative = true)
        link = nil
        return link unless serializer
        return link if obj.is_a?(CodeObjects::Base) && run_verifier([obj]).empty?

        if obj.is_a?(CodeObjects::Base) && !obj.is_a?(CodeObjects::NamespaceObject)
          # If the obj is not a namespace obj make it the anchor.
          anchor = obj
          obj = obj.namespace
        end

        objpath = serializer.serialized_path(obj)
        return link unless objpath

        relative = false if object == Registry.root
        if relative
          fromobj = object
          if object.is_a?(CodeObjects::Base) &&
             !object.is_a?(CodeObjects::NamespaceObject)
            fromobj = owner
          end

          from = serializer.serialized_path(fromobj)
          link = File.relative_path(from, objpath)
        else
          link = objpath
        end

        link + (anchor ? '#' + urlencode(anchor_for(anchor)) : '')
      end

      alias mtime_url url_for
      def mtime(_file) nil end

      # Returns the URL for a specific file
      #
      # @param [String, CodeObjects::ExtraFileObject] filename the filename to link to
      # @param [String] anchor optional anchor
      # @return [String] the URL pointing to the file
      def url_for_file(filename, anchor = nil)
        return '' unless serializer
        fromobj = object
        if CodeObjects::Base === fromobj && !fromobj.is_a?(CodeObjects::NamespaceObject)
          fromobj = fromobj.namespace
        end
        from = serializer.serialized_path(fromobj)
        path = filename == options.readme ?
          'index.html' : serializer.serialized_path(filename)
        link = File.relative_path(from, path)
        link += (anchor ? '#' + urlencode(anchor) : '')
        link
      end

      # Returns the URL for a list type
      #
      # @param [String, Symbol] type the list type to generate a URL for
      # @return [String] the URL pointing to the list
      # @since 0.8.0
      def url_for_list(type)
        url_for_file("#{type}_list.html")
      end

      # Returns the URL for the frameset page
      #
      # @return [String] the URL pointing to the frames page
      # @since 0.8.0
      def url_for_frameset
        url_for_file("frames.html")
      end

      # Returns the URL for the main page (README or alphabetic index)
      #
      # @return [String] the URL pointing to the first main page the
      #   user should see.
      def url_for_main
        url_for_file("index.html")
      end

      # Returns the URL for the alphabetic index page
      #
      # @return [String] the URL pointing to the first main page the
      #   user should see.
      def url_for_index
        url_for_file("_index.html")
      end

      # @group Formatting Objects and Attributes

      # Formats a list of objects and links them
      # @return [String] a formatted list of objects
      def format_object_name_list(objects)
        objects.sort_by {|o| o.name.to_s.downcase }.map do |o|
          "<span class='name'>" + linkify(o, o.name) + "</span>"
        end.join(", ")
      end

      # Formats a list of types from a tag.
      #
      # @param [Array<String>, FalseClass] typelist
      #   the list of types to be formatted.
      #
      # @param [Boolean] brackets omits the surrounding
      #   brackets if +brackets+ is set to +false+.
      #
      # @return [String] the list of types formatted
      #   as [Type1, Type2, ...] with the types linked
      #   to their respective descriptions.
      #
      def format_types(typelist, brackets = true)
        return unless typelist.is_a?(Array)
        list = typelist.map do |type|
          type = type.gsub(/([<>])/) { h($1) }
          type = type.gsub(/([\w:]+)/) { $1 == "lt" || $1 == "gt" ? $1 : linkify($1, $1) }
          "<tt>" + type + "</tt>"
        end
        list.empty? ? "" : (brackets ? "(#{list.join(", ")})" : list.join(", "))
      end

      # Get the return types for a method signature.
      #
      # @param [CodeObjects::MethodObject] meth the method object
      # @param [Boolean] link whether to link the types
      # @return [String] the signature types
      # @since 0.5.3
      def signature_types(meth, link = true)
        meth = convert_method_to_overload(meth)
        if meth.respond_to?(:object) && !meth.has_tag?(:return)
          meth = meth.object
        end

        type = options.default_return || ""
        if meth.tag(:return) && meth.tag(:return).types
          types = meth.tags(:return).map {|t| t.types ? t.types : [] }.flatten.uniq
          first = link ? h(types.first) : format_types([types.first], false)
          if types.size == 2 && types.last == 'nil'
            type = first + '<sup>?</sup>'
          elsif types.size == 2 && types.last =~ /^(Array)?<#{Regexp.quote types.first}>$/
            type = first + '<sup>+</sup>'
          elsif types.size > 2
            type = [first, '...'].join(', ')
          elsif types == ['void'] && options.hide_void_return
            type = ""
          else
            type = link ? h(types.join(", ")) : format_types(types, false)
          end
        elsif !type.empty?
          type = link ? h(type) : format_types([type], false)
        end
        type = "#{type} " unless type.empty?
        type
      end

      # Formats the signature of method +meth+.
      #
      # @param [CodeObjects::MethodObject] meth the method object to list
      #   the signature of
      # @param [Boolean] link whether to link the method signature to the details view
      # @param [Boolean] show_extras whether to show extra meta-data (visibility, attribute info)
      # @param [Boolean] full_attr_name whether to show the full attribute name
      #   ("name=" instead of "name")
      # @return [String] the formatted method signature
      def signature(meth, link = true, show_extras = true, full_attr_name = true)
        meth = convert_method_to_overload(meth)

        type = signature_types(meth, link)
        type = "&#x21d2; #{type}" if type && !type.empty?
        scope = meth.scope == :class ? "." : "#"
        name = full_attr_name ? meth.name : meth.name.to_s.gsub(/^(\w+)=$/, '\1')
        blk = format_block(meth)
        args = !full_attr_name && meth.writer? ? "" : format_args(meth)
        extras = []
        extras_text = ''
        if show_extras
          rw = meth.attr_info
          if rw
            attname = [rw[:read] ? 'read' : nil, rw[:write] ? 'write' : nil].compact
            attname = attname.size == 1 ? attname.join('') + 'only' : nil
            extras << attname if attname
          end
          extras << meth.visibility if meth.visibility != :public
          extras_text = ' <span class="extras">(' + extras.join(", ") + ')</span>' unless extras.empty?
        end
        title = "%s<strong>%s</strong>%s %s %s" % [scope, h(name), args, blk, type]
        if link
          if meth.is_a?(YARD::CodeObjects::MethodObject)
            link_title = "#{h meth.name(true)} (#{meth.scope} #{meth.type})"
          else
            link_title = "#{h name} (#{meth.type})"
          end
          obj = meth.respond_to?(:object) ? meth.object : meth
          url = url_for(object, obj)
          link_url(url, title, :title => link_title) + extras_text
        else
          title + extras_text
        end
      end

      # @group Getting the Character Encoding

      # Returns the current character set. The default value can be overridden
      # by setting the +LANG+ environment variable or by overriding this
      # method. In Ruby 1.9 you can also modify this value by setting
      # +Encoding.default_external+.
      #
      # @return [String] the current character set
      # @since 0.5.4
      def charset
        has_encoding = defined?(::Encoding)
        if defined?(@file) && @file && has_encoding
          lang = @file.contents.encoding.to_s
        else
          return 'utf-8' unless has_encoding || ENV['LANG']
          lang =
            if has_encoding
              ::Encoding.default_external.name.downcase
            else
              ENV['LANG'].downcase.split('.').last
            end
        end

        case lang
        when "ascii-8bit", "us-ascii", "ascii-7bit"; 'iso-8859-1'
        when "utf8"; 'utf-8'
        else; lang
        end
      end

      # @endgroup

      private

      # Converts a set of hash options into HTML attributes for a tag
      #
      # @param [Hash{String => String}] opts the tag options
      # @return [String] the tag attributes of an HTML tag
      def tag_attrs(opts = {})
        opts.sort_by {|k, _v| k.to_s }.map {|k, v| "#{k}=#{v.to_s.inspect}" if v }.join(" ")
      end

      # Converts a {CodeObjects::MethodObject} into an overload object
      # @since 0.5.3
      def convert_method_to_overload(meth)
        # use first overload tag if it has a return type and method itself does not
        if !meth.tag(:return) && meth.tags(:overload).size == 1 && meth.tag(:overload).tag(:return)
          return meth.tag(:overload)
        end
        meth
      end

      # Parses !!!lang out of codeblock, returning the codeblock language
      # followed by the source code.
      #
      # @param [String] source the source code whose language to determine
      # @return [Array(String, String)] the language, if any, and the
      #   remaining source
      # @since 0.7.5
      def parse_lang_for_codeblock(source)
        type = nil
        if source =~ /\A(?:[ \t]*\r?\n)?[ \t]*!!!([\w.+-]+)[ \t]*\r?\n/
          type = $1
          source = $'
        end

        [type, source]
      end

      # Parses code blocks out of html and performs syntax highlighting
      # on code inside of the blocks.
      #
      # @param [String] html the html to search for code in
      # @return [String] highlighted html
      # @see #html_syntax_highlight
      def parse_codeblocks(html)
        html.gsub(%r{<pre\s*(?:lang="(.+?)")?>(?:\s*<code\s*(?:class="(.+?)")?\s*>)?(.+?)(?:</code>\s*)?</pre>}m) do
          string = $3
          # handle !!!LANG prefix to send to html_syntax_highlight_LANG
          language, = parse_lang_for_codeblock(string)
          language ||= $1 || $2 || object.source_type

          if options.highlight
            string = html_syntax_highlight(CGI.unescapeHTML(string), language)
          end
          classes = ['code', language].compact.join(' ')
          %(<pre class="#{classes}"><code class="#{language}">#{string}</code></pre>)
        end
      end
    end
  end
end
