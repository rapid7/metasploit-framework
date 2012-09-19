require 'stringio'
require 'nokogiri/xml/node/save_options'

module Nokogiri
  module XML
    ####
    # Nokogiri::XML::Node is your window to the fun filled world of dealing
    # with XML and HTML tags.  A Nokogiri::XML::Node may be treated similarly
    # to a hash with regard to attributes.  For example (from irb):
    #
    #   irb(main):004:0> node
    #   => <a href="#foo" id="link">link</a>
    #   irb(main):005:0> node['href']
    #   => "#foo"
    #   irb(main):006:0> node.keys
    #   => ["href", "id"]
    #   irb(main):007:0> node.values
    #   => ["#foo", "link"]
    #   irb(main):008:0> node['class'] = 'green'
    #   => "green"
    #   irb(main):009:0> node
    #   => <a href="#foo" id="link" class="green">link</a>
    #   irb(main):010:0>
    #
    # See Nokogiri::XML::Node#[] and Nokogiri::XML#[]= for more information.
    #
    # Nokogiri::XML::Node also has methods that let you move around your
    # tree.  For navigating your tree, see:
    #
    # * Nokogiri::XML::Node#parent
    # * Nokogiri::XML::Node#children
    # * Nokogiri::XML::Node#next
    # * Nokogiri::XML::Node#previous
    #
    # You may search this node's subtree using Node#xpath and Node#css
    class Node
      include Nokogiri::XML::PP::Node
      include Enumerable

      # Element node type, see Nokogiri::XML::Node#element?
      ELEMENT_NODE =       1
      # Attribute node type
      ATTRIBUTE_NODE =     2
      # Text node type, see Nokogiri::XML::Node#text?
      TEXT_NODE =          3
      # CDATA node type, see Nokogiri::XML::Node#cdata?
      CDATA_SECTION_NODE = 4
      # Entity reference node type
      ENTITY_REF_NODE =    5
      # Entity node type
      ENTITY_NODE =        6
      # PI node type
      PI_NODE =            7
      # Comment node type, see Nokogiri::XML::Node#comment?
      COMMENT_NODE =       8
      # Document node type, see Nokogiri::XML::Node#xml?
      DOCUMENT_NODE =      9
      # Document type node type
      DOCUMENT_TYPE_NODE = 10
      # Document fragment node type
      DOCUMENT_FRAG_NODE = 11
      # Notation node type
      NOTATION_NODE =      12
      # HTML document node type, see Nokogiri::XML::Node#html?
      HTML_DOCUMENT_NODE = 13
      # DTD node type
      DTD_NODE =           14
      # Element declaration type
      ELEMENT_DECL =       15
      # Attribute declaration type
      ATTRIBUTE_DECL =     16
      # Entity declaration type
      ENTITY_DECL =        17
      # Namespace declaration type
      NAMESPACE_DECL =     18
      # XInclude start type
      XINCLUDE_START =     19
      # XInclude end type
      XINCLUDE_END =       20
      # DOCB document node type
      DOCB_DOCUMENT_NODE = 21

      def initialize name, document # :nodoc:
        # ... Ya.  This is empty on purpose.
      end

      ###
      # Decorate this node with the decorators set up in this node's Document
      def decorate!
        document.decorate(self)
      end

      ###
      # Search this node for +paths+.  +paths+ can be XPath or CSS, and an
      # optional hash of namespaces may be appended.
      # See Node#xpath and Node#css.
      def search *paths
        # TODO use         paths, handler, ns, binds = extract_params(paths)
        ns = paths.last.is_a?(Hash) ? paths.pop :
          (document.root ? document.root.namespaces : {})

        prefix = "#{implied_xpath_context}/"

        xpath(*(paths.map { |path|
          path = path.to_s
          path =~ /^(\.\/|\/|\.\.)/ ? path : CSS.xpath_for(
            path,
            :prefix => prefix,
            :ns     => ns
          )
        }.flatten.uniq) + [ns])
      end
      alias :/ :search

      ###
      # call-seq: xpath *paths, [namespace-bindings, variable-bindings, custom-handler-class]
      #
      # Search this node for XPath +paths+. +paths+ must be one or more XPath
      # queries.
      #
      #   node.xpath('.//title')
      #
      # A hash of namespace bindings may be appended. For example:
      #
      #   node.xpath('.//foo:name', {'foo' => 'http://example.org/'})
      #   node.xpath('.//xmlns:name', node.root.namespaces)
      #
      # A hash of variable bindings may also be appended to the namespace bindings. For example:
      #
      #   node.xpath('.//address[@domestic=$value]', nil, {:value => 'Yes'})
      #
      # Custom XPath functions may also be defined.  To define custom
      # functions create a class and implement the function you want
      # to define.  The first argument to the method will be the
      # current matching NodeSet.  Any other arguments are ones that
      # you pass in.  Note that this class may appear anywhere in the
      # argument list.  For example:
      #
      #   node.xpath('.//title[regex(., "\w+")]', Class.new {
      #     def regex node_set, regex
      #       node_set.find_all { |node| node['some_attribute'] =~ /#{regex}/ }
      #     end
      #   }.new)
      #
      def xpath *paths
        return NodeSet.new(document) unless document

        paths, handler, ns, binds = extract_params(paths)

        sets = paths.map { |path|
          ctx = XPathContext.new(self)
          ctx.register_namespaces(ns)
          path = path.gsub(/\/xmlns:/,'/:') unless Nokogiri.uses_libxml?

          binds.each do |key,value|
            ctx.register_variable key.to_s, value
          end if binds

          ctx.evaluate(path, handler)
        }
        return sets.first if sets.length == 1

        NodeSet.new(document) do |combined|
          sets.each do |set|
            set.each do |node|
              combined << node
            end
          end
        end
      end

      ###
      # call-seq: css *rules, [namespace-bindings, custom-pseudo-class]
      #
      # Search this node for CSS +rules+. +rules+ must be one or more CSS
      # selectors. For example:
      #
      #   node.css('title')
      #   node.css('body h1.bold')
      #   node.css('div + p.green', 'div#one')
      #
      # A hash of namespace bindings may be appended. For example:
      #
      #   node.css('bike|tire', {'bike' => 'http://schwinn.com/'})
      #
      # Custom CSS pseudo classes may also be defined.  To define
      # custom pseudo classes, create a class and implement the custom
      # pseudo class you want defined.  The first argument to the
      # method will be the current matching NodeSet.  Any other
      # arguments are ones that you pass in.  For example:
      #
      #   node.css('title:regex("\w+")', Class.new {
      #     def regex node_set, regex
      #       node_set.find_all { |node| node['some_attribute'] =~ /#{regex}/ }
      #     end
      #   }.new)
      #
      # Note that the CSS query string is case-sensitive with regards
      # to your document type. That is, if you're looking for "H1" in
      # an HTML document, you'll never find anything, since HTML tags
      # will match only lowercase CSS queries. However, "H1" might be
      # found in an XML document, where tags names are case-sensitive
      # (e.g., "H1" is distinct from "h1").
      #
      def css *rules
        rules, handler, ns, binds = extract_params(rules)

        prefix = "#{implied_xpath_context}/"

        rules = rules.map { |rule|
          CSS.xpath_for(rule, :prefix => prefix, :ns => ns)
        }.flatten.uniq + [ns, handler, binds].compact

        xpath(*rules)
      end

      ###
      # Search this node's immediate children using CSS selector +selector+
      def > selector
        ns = document.root.namespaces
        xpath CSS.xpath_for(selector, :prefix => "./", :ns => ns).first
      end

      ###
      # Search for the first occurrence of +path+.
      #
      # Returns nil if nothing is found, otherwise a Node.
      def at path, ns = document.root ? document.root.namespaces : {}
        search(path, ns).first
      end
      alias :% :at

      ##
      # Search this node for the first occurrence of XPath +paths+.
      # Equivalent to <tt>xpath(paths).first</tt>
      # See Node#xpath for more information.
      #
      def at_xpath *paths
        xpath(*paths).first
      end

      ##
      # Search this node for the first occurrence of CSS +rules+.
      # Equivalent to <tt>css(rules).first</tt>
      # See Node#css for more information.
      #
      def at_css *rules
        css(*rules).first
      end

      ###
      # Get the attribute value for the attribute +name+
      def [] name
        return nil unless key?(name.to_s)
        get(name.to_s)
      end

      ###
      # Set the attribute value for the attribute +name+ to +value+
      def []= name, value
        set name.to_s, value
      end

      ###
      # Add +node_or_tags+ as a child of this Node.
      # +node_or_tags+ can be a Nokogiri::XML::Node, a ::DocumentFragment, a ::NodeSet, or a string containing markup.
      #
      # Returns the reparented node (if +node_or_tags+ is a Node), or NodeSet (if +node_or_tags+ is a DocumentFragment, NodeSet, or string).
      #
      # Also see related method +<<+.
      def add_child node_or_tags
        node_or_tags = coerce(node_or_tags)
        if node_or_tags.is_a?(XML::NodeSet)
          node_or_tags.each { |n| add_child_node n }
        else
          add_child_node node_or_tags
        end
        node_or_tags
      end

      ###
      # Add +node_or_tags+ as a child of this Node.
      # +node_or_tags+ can be a Nokogiri::XML::Node, a ::DocumentFragment, a ::NodeSet, or a string containing markup.
      #
      # Returns self, to support chaining of calls (e.g., root << child1 << child2)
      #
      # Also see related method +add_child+.
      def << node_or_tags
        add_child node_or_tags
        self
      end
      ###
      # Insert +node_or_tags+ before this Node (as a sibling).
      # +node_or_tags+ can be a Nokogiri::XML::Node, a ::DocumentFragment, a ::NodeSet, or a string containing markup.
      #
      # Returns the reparented node (if +node_or_tags+ is a Node), or NodeSet (if +node_or_tags+ is a DocumentFragment, NodeSet, or string).
      #
      # Also see related method +before+.
      def add_previous_sibling node_or_tags
        raise ArgumentError.new("A document may not have multiple root nodes.") if parent.is_a?(XML::Document) && !node_or_tags.is_a?(XML::ProcessingInstruction)

        node_or_tags = coerce(node_or_tags)
        if node_or_tags.is_a?(XML::NodeSet)
          if text?
            pivot = Nokogiri::XML::Node.new 'dummy', document
            add_previous_sibling_node pivot
          else
            pivot = self
          end
          node_or_tags.each { |n| pivot.send :add_previous_sibling_node, n }
          pivot.unlink if text?
        else
          add_previous_sibling_node node_or_tags
        end
        node_or_tags
      end

      ###
      # Insert +node_or_tags+ after this Node (as a sibling).
      # +node_or_tags+ can be a Nokogiri::XML::Node, a ::DocumentFragment, a ::NodeSet, or a string containing markup.
      #
      # Returns the reparented node (if +node_or_tags+ is a Node), or NodeSet (if +node_or_tags+ is a DocumentFragment, NodeSet, or string).
      #
      # Also see related method +after+.
      def add_next_sibling node_or_tags
        raise ArgumentError.new("A document may not have multiple root nodes.") if parent.is_a?(XML::Document)
        
        node_or_tags = coerce(node_or_tags)
        if node_or_tags.is_a?(XML::NodeSet)
          if text?
            pivot = Nokogiri::XML::Node.new 'dummy', document
            add_next_sibling_node pivot
          else
            pivot = self
          end
          node_or_tags.reverse_each { |n| pivot.send :add_next_sibling_node, n }
          pivot.unlink if text?
        else
          add_next_sibling_node node_or_tags
        end
        node_or_tags
      end

      ####
      # Insert +node_or_tags+ before this node (as a sibling).
      # +node_or_tags+ can be a Nokogiri::XML::Node, a ::DocumentFragment, a ::NodeSet, or a string containing markup.
      #
      # Returns self, to support chaining of calls.
      #
      # Also see related method +add_previous_sibling+.
      def before node_or_tags
        add_previous_sibling node_or_tags
        self
      end

      ####
      # Insert +node_or_tags+ after this node (as a sibling).
      # +node_or_tags+ can be a Nokogiri::XML::Node, a Nokogiri::XML::DocumentFragment, or a string containing markup.
      #
      # Returns self, to support chaining of calls.
      #
      # Also see related method +add_next_sibling+.
      def after node_or_tags
        add_next_sibling node_or_tags
        self
      end

      ####
      # Set the inner html for this Node to +node_or_tags+
      # +node_or_tags+ can be a Nokogiri::XML::Node, a Nokogiri::XML::DocumentFragment, or a string containing markup.
      #
      # Returns self.
      #
      # Also see related method +children=+
      def inner_html= node_or_tags
        self.children = node_or_tags
        self
      end

      ####
      # Set the inner html for this Node +node_or_tags+
      # +node_or_tags+ can be a Nokogiri::XML::Node, a Nokogiri::XML::DocumentFragment, or a string containing markup.
      #
      # Returns the reparented node (if +node_or_tags+ is a Node), or NodeSet (if +node_or_tags+ is a DocumentFragment, NodeSet, or string).
      #
      # Also see related method +inner_html=+
      def children= node_or_tags
        node_or_tags = coerce(node_or_tags)
        children.unlink
        if node_or_tags.is_a?(XML::NodeSet)
          node_or_tags.each { |n| add_child_node n }
        else
          add_child_node node_or_tags
        end
        node_or_tags
      end

      ####
      # Replace this Node with +node_or_tags+.
      # +node_or_tags+ can be a Nokogiri::XML::Node, a ::DocumentFragment, a ::NodeSet, or a string containing markup.
      #
      # Returns the reparented node (if +node_or_tags+ is a Node), or NodeSet (if +node_or_tags+ is a DocumentFragment, NodeSet, or string).
      #
      # Also see related method +swap+.
      def replace node_or_tags
        node_or_tags = coerce(node_or_tags)
        if node_or_tags.is_a?(XML::NodeSet)
          if text?
            replacee = Nokogiri::XML::Node.new 'dummy', document
            add_previous_sibling_node replacee
            unlink
          else
            replacee = self
          end
          node_or_tags.each { |n| replacee.add_previous_sibling n }
          replacee.unlink
        else
          replace_node node_or_tags
        end
        node_or_tags
      end

      ####
      # Swap this Node for +node_or_tags+
      # +node_or_tags+ can be a Nokogiri::XML::Node, a ::DocumentFragment, a ::NodeSet, or a string containing markup.
      #
      # Returns self, to support chaining of calls.
      #
      # Also see related method +replace+.
      def swap node_or_tags
        replace node_or_tags
        self
      end

      alias :next           :next_sibling
      alias :previous       :previous_sibling

      # :stopdoc:
      # HACK: This is to work around an RDoc bug
      alias :next=          :add_next_sibling
      # :startdoc:

      alias :previous=      :add_previous_sibling
      alias :remove         :unlink
      alias :get_attribute  :[]
      alias :attr           :[]
      alias :set_attribute  :[]=
      alias :text           :content
      alias :inner_text     :content
      alias :has_attribute? :key?
      alias :name           :node_name
      alias :name=          :node_name=
      alias :type           :node_type
      alias :to_str         :text
      alias :clone          :dup
      alias :elements       :element_children

      ####
      # Returns a hash containing the node's attributes.  The key is
      # the attribute name without any namespace, the value is a Nokogiri::XML::Attr
      # representing the attribute.
      # If you need to distinguish attributes with the same name, with different namespaces
      # use #attribute_nodes instead.
      def attributes
        Hash[attribute_nodes.map { |node|
          [node.node_name, node]
        }]
      end

      ###
      # Get the attribute values for this Node.
      def values
        attribute_nodes.map { |node| node.value }
      end

      ###
      # Get the attribute names for this Node.
      def keys
        attribute_nodes.map { |node| node.node_name }
      end

      ###
      # Iterate over each attribute name and value pair for this Node.
      def each
        attribute_nodes.each { |node|
          yield [node.node_name, node.value]
        }
      end

      ###
      # Remove the attribute named +name+
      def remove_attribute name
        attributes[name].remove if key? name
      end
      alias :delete :remove_attribute

      ###
      # Returns true if this Node matches +selector+
      def matches? selector
        ancestors.last.search(selector).include?(self)
      end

      ###
      # Create a DocumentFragment containing +tags+ that is relative to _this_
      # context node.
      def fragment tags
        type = document.html? ? Nokogiri::HTML : Nokogiri::XML
        type::DocumentFragment.new(document, tags, self)
      end

      ###
      # Parse +string_or_io+ as a document fragment within the context of
      # *this* node.  Returns a XML::NodeSet containing the nodes parsed from
      # +string_or_io+.
      def parse string_or_io, options = nil
        options ||= (document.html? ? ParseOptions::DEFAULT_HTML : ParseOptions::DEFAULT_XML)
        if Fixnum === options
          options = Nokogiri::XML::ParseOptions.new(options)
        end
        # Give the options to the user
        yield options if block_given?

        contents = string_or_io.respond_to?(:read) ?
          string_or_io.read :
          string_or_io

        return Nokogiri::XML::NodeSet.new(document) if contents.empty?

        ##
        # This is a horrible hack, but I don't care. See #313 for background.
        error_count = document.errors.length
        node_set = in_context(contents, options.to_i)
        if node_set.empty? and document.errors.length > error_count and options.recover?
          fragment = Nokogiri::HTML::DocumentFragment.parse contents
          node_set = fragment.children
        end
        node_set
      end

      ####
      # Set the Node's content to a Text node containing +string+. The string gets XML escaped, not interpreted as markup.
      def content= string
        self.native_content = encode_special_chars(string.to_s)
      end

      ###
      # Set the parent Node for this Node
      def parent= parent_node
        parent_node.add_child(self)
        parent_node
      end

      ###
      # Returns a Hash of {prefix => value} for all namespaces on this
      # node and its ancestors.
      #
      # This method returns the same namespaces as #namespace_scopes.
      #
      # Returns namespaces in scope for self -- those defined on self
      # element directly or any ancestor node -- as a Hash of
      # attribute-name/value pairs. Note that the keys in this hash
      # XML attributes that would be used to define this namespace,
      # such as "xmlns:prefix", not just the prefix. Default namespace
      # set on self will be included with key "xmlns". However,
      # default namespaces set on ancestor will NOT be, even if self
      # has no explicit default namespace.
      def namespaces
        Hash[namespace_scopes.map { |nd|
          key = ['xmlns', nd.prefix].compact.join(':')
          if RUBY_VERSION >= '1.9' && document.encoding
            begin
              key.force_encoding document.encoding
            rescue ArgumentError
            end
          end
          [key, nd.href]
        }]
      end

      # Returns true if this is a Comment
      def comment?
        type == COMMENT_NODE
      end

      # Returns true if this is a CDATA
      def cdata?
        type == CDATA_SECTION_NODE
      end

      # Returns true if this is an XML::Document node
      def xml?
        type == DOCUMENT_NODE
      end

      # Returns true if this is an HTML::Document node
      def html?
        type == HTML_DOCUMENT_NODE
      end

      # Returns true if this is a Text node
      def text?
        type == TEXT_NODE
      end

      # Returns true if this is a DocumentFragment
      def fragment?
        type == DOCUMENT_FRAG_NODE
      end

      ###
      # Fetch the Nokogiri::HTML::ElementDescription for this node.  Returns
      # nil on XML documents and on unknown tags.
      def description
        return nil if document.xml?
        Nokogiri::HTML::ElementDescription[name]
      end

      ###
      # Is this a read only node?
      def read_only?
        # According to gdome2, these are read-only node types
        [NOTATION_NODE, ENTITY_NODE, ENTITY_DECL].include?(type)
      end

      # Returns true if this is an Element node
      def element?
        type == ELEMENT_NODE
      end
      alias :elem? :element?

      ###
      # Turn this node in to a string.  If the document is HTML, this method
      # returns html.  If the document is XML, this method returns XML.
      def to_s
        document.xml? ? to_xml : to_html
      end

      # Get the inner_html for this node's Node#children
      def inner_html *args
        children.map { |x| x.to_html(*args) }.join
      end

      # Get the path to this node as a CSS expression
      def css_path
        path.split(/\//).map { |part|
          part.length == 0 ? nil : part.gsub(/\[(\d+)\]/, ':nth-of-type(\1)')
        }.compact.join(' > ')
      end

      ###
      # Get a list of ancestor Node for this Node.  If +selector+ is given,
      # the ancestors must match +selector+
      def ancestors selector = nil
        return NodeSet.new(document) unless respond_to?(:parent)
        return NodeSet.new(document) unless parent

        parents = [parent]

        while parents.last.respond_to?(:parent)
          break unless ctx_parent = parents.last.parent
          parents << ctx_parent
        end

        return NodeSet.new(document, parents) unless selector

        root = parents.last

        NodeSet.new(document, parents.find_all { |parent|
          root.search(selector).include?(parent)
        })
      end

      ###
      # Adds a default namespace supplied as a string +url+ href, to self.
      # The consequence is as an xmlns attribute with supplied argument were
      # present in parsed XML.  A default namespace set with this method will
      # now show up in #attributes, but when this node is serialized to XML an
      # "xmlns" attribute will appear. See also #namespace and #namespace=
      def default_namespace= url
        add_namespace_definition(nil, url)
      end
      alias :add_namespace :add_namespace_definition

      ###
      # Set the default namespace on this node (as would be defined with an
      # "xmlns=" attribute in XML source), as a Namespace object +ns+. Note that
      # a Namespace added this way will NOT be serialized as an xmlns attribute
      # for this node. You probably want #default_namespace= instead, or perhaps
      # #add_namespace_definition with a nil prefix argument.
      def namespace= ns
        return set_namespace(ns) unless ns

        unless Nokogiri::XML::Namespace === ns
          raise TypeError, "#{ns.class} can't be coerced into Nokogiri::XML::Namespace"
        end
        if ns.document != document
          raise ArgumentError, 'namespace must be declared on the same document'
        end

        set_namespace ns
      end

      ####
      # Yields self and all children to +block+ recursively.
      def traverse &block
        children.each{|j| j.traverse(&block) }
        block.call(self)
      end

      ###
      # Accept a visitor.  This method calls "visit" on +visitor+ with self.
      def accept visitor
        visitor.visit(self)
      end

      ###
      # Test to see if this Node is equal to +other+
      def == other
        return false unless other
        return false unless other.respond_to?(:pointer_id)
        pointer_id == other.pointer_id
      end

      ###
      # Serialize Node using +options+.  Save options can also be set using a
      # block. See SaveOptions.
      #
      # These two statements are equivalent:
      #
      #  node.serialize(:encoding => 'UTF-8', :save_with => FORMAT | AS_XML)
      #
      # or
      #
      #   node.serialize(:encoding => 'UTF-8') do |config|
      #     config.format.as_xml
      #   end
      #
      def serialize *args, &block
        options = args.first.is_a?(Hash) ? args.shift : {
          :encoding   => args[0],
          :save_with  => args[1]
        }

        encoding = options[:encoding] || document.encoding
        options[:encoding] = encoding

        outstring = ""
        if encoding && outstring.respond_to?(:force_encoding)
          outstring.force_encoding(Encoding.find(encoding))
        end
        io = StringIO.new(outstring)
        write_to io, options, &block
        io.string
      end

      ###
      # Serialize this Node to HTML
      #
      #   doc.to_html
      #
      # See Node#write_to for a list of +options+.  For formatted output,
      # use Node#to_xhtml instead.
      def to_html options = {}
        # FIXME: this is a hack around broken libxml versions
        return dump_html if Nokogiri.uses_libxml? && %w[2 6] === LIBXML_VERSION.split('.')[0..1]

        options[:save_with] |= SaveOptions::DEFAULT_HTML if options[:save_with]
        options[:save_with] = SaveOptions::DEFAULT_HTML unless options[:save_with]
        serialize(options)
      end

      ###
      # Serialize this Node to XML using +options+
      #
      #   doc.to_xml(:indent => 5, :encoding => 'UTF-8')
      #
      # See Node#write_to for a list of +options+
      def to_xml options = {}
        options[:save_with] ||= SaveOptions::DEFAULT_XML
        serialize(options)
      end

      ###
      # Serialize this Node to XHTML using +options+
      #
      #   doc.to_xhtml(:indent => 5, :encoding => 'UTF-8')
      #
      # See Node#write_to for a list of +options+
      def to_xhtml options = {}
        # FIXME: this is a hack around broken libxml versions
        return dump_html if Nokogiri.uses_libxml? && %w[2 6] === LIBXML_VERSION.split('.')[0..1]

        options[:save_with] |= SaveOptions::DEFAULT_XHTML if options[:save_with]
        options[:save_with] = SaveOptions::DEFAULT_XHTML unless options[:save_with]
        serialize(options)
      end

      ###
      # Write Node to +io+ with +options+. +options+ modify the output of
      # this method.  Valid options are:
      #
      # * +:encoding+ for changing the encoding
      # * +:indent_text+ the indentation text, defaults to one space
      # * +:indent+ the number of +:indent_text+ to use, defaults to 2
      # * +:save_with+ a combination of SaveOptions constants.
      #
      # To save with UTF-8 indented twice:
      #
      #   node.write_to(io, :encoding => 'UTF-8', :indent => 2)
      #
      # To save indented with two dashes:
      #
      #   node.write_to(io, :indent_text => '-', :indent => 2
      #
      def write_to io, *options
        options       = options.first.is_a?(Hash) ? options.shift : {}
        encoding      = options[:encoding] || options[0]
        if Nokogiri.jruby?
          save_options  = options[:save_with] || options[1]
          indent_times  = options[:indent] || 0
        else
          save_options  = options[:save_with] || options[1] || SaveOptions::FORMAT
          indent_times  = options[:indent] || 2
        end
        indent_text   = options[:indent_text] || ' '

        config = SaveOptions.new(save_options.to_i)
        yield config if block_given?

        native_write_to(io, encoding, indent_text * indent_times, config.options)
      end

      ###
      # Write Node as HTML to +io+ with +options+
      #
      # See Node#write_to for a list of +options+
      def write_html_to io, options = {}
        # FIXME: this is a hack around broken libxml versions
        return (io << dump_html) if Nokogiri.uses_libxml? && %w[2 6] === LIBXML_VERSION.split('.')[0..1]

        options[:save_with] ||= SaveOptions::DEFAULT_HTML
        write_to io, options
      end

      ###
      # Write Node as XHTML to +io+ with +options+
      #
      # See Node#write_to for a list of +options+
      def write_xhtml_to io, options = {}
        # FIXME: this is a hack around broken libxml versions
        return (io << dump_html) if Nokogiri.uses_libxml? && %w[2 6] === LIBXML_VERSION.split('.')[0..1]

        options[:save_with] ||= SaveOptions::DEFAULT_XHTML
        write_to io, options
      end

      ###
      # Write Node as XML to +io+ with +options+
      #
      #   doc.write_xml_to io, :encoding => 'UTF-8'
      #
      # See Node#write_to for a list of options
      def write_xml_to io, options = {}
        options[:save_with] ||= SaveOptions::DEFAULT_XML
        write_to io, options
      end

      ###
      # Compare two Node objects with respect to their Document.  Nodes from
      # different documents cannot be compared.
      def <=> other
        return nil unless other.is_a?(Nokogiri::XML::Node)
        return nil unless document == other.document
        compare other
      end

      ###
      # Do xinclude substitution on the subtree below node. If given a block, a
      # Nokogiri::XML::ParseOptions object initialized from +options+, will be
      # passed to it, allowing more convenient modification of the parser options.
      def do_xinclude options = XML::ParseOptions::DEFAULT_XML, &block
        options = Nokogiri::XML::ParseOptions.new(options) if Fixnum === options

        # give options to user
        yield options if block_given?

        # call c extension
        process_xincludes(options.to_i)
      end

      def canonicalize(mode=XML::XML_C14N_1_0,inclusive_namespaces=nil,with_comments=false)
        c14n_root = self
        document.canonicalize(mode, inclusive_namespaces, with_comments) do |node, parent|
          tn = node.is_a?(XML::Node) ? node : parent
          tn == c14n_root || tn.ancestors.include?(c14n_root)
        end
      end

      private

      def extract_params params # :nodoc:
        # Pop off our custom function handler if it exists
        handler = params.find { |param|
          ![Hash, String, Symbol].include?(param.class)
        }

        params -= [handler] if handler

        hashes = []
        while Hash === params.last || params.last.nil?
          hashes << params.pop
          break if params.empty?
        end

        ns, binds = hashes.reverse

        ns ||= document.root ? document.root.namespaces : {}

        [params, handler, ns, binds]
      end

      def coerce data # :nodoc:
        return data                    if data.is_a?(XML::NodeSet)
        return data.children           if data.is_a?(XML::DocumentFragment)
        return fragment(data).children if data.is_a?(String)

        if data.is_a?(Document) || data.is_a?(XML::Attr) || !data.is_a?(XML::Node)
          raise ArgumentError, <<-EOERR
Requires a Node, NodeSet or String argument, and cannot accept a #{data.class}.
(You probably want to select a node from the Document with at() or search(), or create a new Node via Node.new().)
          EOERR
        end

        data
      end

      def implied_xpath_context
        "./"
      end

      def inspect_attributes
        [:name, :namespace, :attribute_nodes, :children]
      end
    end
  end
end
