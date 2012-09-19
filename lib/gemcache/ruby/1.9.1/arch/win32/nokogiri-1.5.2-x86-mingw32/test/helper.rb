#Process.setrlimit(Process::RLIMIT_CORE, Process::RLIM_INFINITY) unless RUBY_PLATFORM =~ /(java|mswin|mingw)/i
$VERBOSE = true
require 'minitest/autorun'
require 'fileutils'
require 'tempfile'
require 'pp'

require 'nokogiri'

warn "#{__FILE__}:#{__LINE__}: version info: #{Nokogiri::VERSION_INFO.inspect}"

module Nokogiri
  class TestCase < MiniTest::Spec
    ASSETS_DIR      = File.expand_path File.join(File.dirname(__FILE__), 'files')
    XML_FILE        = File.join(ASSETS_DIR, 'staff.xml')
    XSLT_FILE       = File.join(ASSETS_DIR, 'staff.xslt')
    EXSLT_FILE      = File.join(ASSETS_DIR, 'exslt.xslt')
    EXML_FILE       = File.join(ASSETS_DIR, 'exslt.xml')
    HTML_FILE       = File.join(ASSETS_DIR, 'tlm.html')
    NICH_FILE       = File.join(ASSETS_DIR, '2ch.html')
    SHIFT_JIS_XML   = File.join(ASSETS_DIR, 'shift_jis.xml')
    SHIFT_JIS_HTML  = File.join(ASSETS_DIR, 'shift_jis.html')
    ENCODING_XHTML_FILE = File.join(ASSETS_DIR, 'encoding.xhtml')
    ENCODING_HTML_FILE  = File.join(ASSETS_DIR, 'encoding.html')
    NOENCODING_FILE  = File.join(ASSETS_DIR, 'noencoding.html')
    METACHARSET_FILE  = File.join(ASSETS_DIR, 'metacharset.html')
    PO_XML_FILE     = File.join(ASSETS_DIR, 'po.xml')
    PO_SCHEMA_FILE  = File.join(ASSETS_DIR, 'po.xsd')
    ADDRESS_SCHEMA_FILE = File.join(ASSETS_DIR, 'address_book.rlx')
    ADDRESS_XML_FILE = File.join(ASSETS_DIR, 'address_book.xml')
    SNUGGLES_FILE   = File.join(ASSETS_DIR, 'snuggles.xml')
    XML_XINCLUDE_FILE = File.join(ASSETS_DIR, 'xinclude.xml')

    def teardown
      if ENV['NOKOGIRI_GC']
        STDOUT.putc '!'
        if RUBY_PLATFORM =~ /java/
          require 'java'
          java.lang.System.gc
        else
          GC.start
        end
      end
    end

    def assert_indent amount, doc, message = nil
      nodes = []
      doc.traverse do |node|
        nodes << node if node.text? && node.blank?
      end
      assert nodes.length > 0
      nodes.each do |node|
        len = node.content.gsub(/[\r\n]/, '').length
        assert_equal(0, len % amount, message)
      end
    end

    def util_decorate(document, decorator_module)
      document.decorators(XML::Node) << decorator_module
      document.decorators(XML::NodeSet) << decorator_module
      document.decorate!
    end

    #
    #  Test::Unit backwards compatibility section
    #
    alias :assert_no_match      :refute_match
    alias :assert_not_nil       :refute_nil
    alias :assert_raise         :assert_raises
    alias :assert_not_equal     :refute_equal

    def assert_nothing_raised(*args)
      self._assertions += 1
      if Module === args.last
        msg = nil
      else
        msg = args.pop
      end
      begin
        line = __LINE__; yield
      rescue Exception => e
        bt = e.backtrace
        as = e.instance_of?(MiniTest::Assertion)
        if as
          ans = /\A#{Regexp.quote(__FILE__)}:#{line}:in /o
          bt.reject! {|ln| ans =~ ln}
        end
        if ((args.empty? && !as) ||
            args.any? {|a| a.instance_of?(Module) ? e.is_a?(a) : e.class == a })
          msg = message(msg) { "Exception raised:\n<#{mu_pp(e)}>" }
          raise MiniTest::Assertion, msg.call, bt
        else
          raise
        end
      end
      nil
    end
  end

  module SAX
    class TestCase < Nokogiri::TestCase
      class Doc < XML::SAX::Document
        attr_reader :start_elements, :start_document_called
        attr_reader :end_elements, :end_document_called
        attr_reader :data, :comments, :cdata_blocks, :start_elements_namespace
        attr_reader :errors, :warnings, :end_elements_namespace
        attr_reader :xmldecls

        def xmldecl version, encoding, standalone
          @xmldecls = [version, encoding, standalone].compact
          super
        end

        def start_document
          @start_document_called = true
          super
        end

        def end_document
          @end_document_called = true
          super
        end

        def error error
          (@errors ||= []) << error
          super
        end

        def warning warning
          (@warning ||= []) << warning
          super
        end

        def start_element *args
          (@start_elements ||= []) << args
          super
        end

        def start_element_namespace *args
          (@start_elements_namespace ||= []) << args
          super
        end

        def end_element *args
          (@end_elements ||= []) << args
          super
        end

        def end_element_namespace *args
          (@end_elements_namespace ||= []) << args
          super
        end

        def characters string
          @data ||= []
          @data += [string]
          super
        end

        def comment string
          @comments ||= []
          @comments += [string]
          super
        end

        def cdata_block string
          @cdata_blocks ||= []
          @cdata_blocks += [string]
          super
        end
      end
    end
  end
end
