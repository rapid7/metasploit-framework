# -*- ruby encoding: utf-8 -*-

require 'rubygems'
require 'hoe'

Hoe.plugin :doofus
Hoe.plugin :gemspec
Hoe.plugin :rubyforge
Hoe.plugin :git
Hoe.plugin :minitest

spec = Hoe.spec 'mime-types' do
  self.rubyforge_name = self.name

  developer('Austin Ziegler', 'austin@rubyforge.org')

  self.remote_rdoc_dir = '.'
  self.rsync_args << ' --exclude=statsvn/'

  self.history_file = 'History.rdoc'
  self.readme_file = 'README.rdoc'
  self.extra_rdoc_files = FileList["*.rdoc"].to_a

  self.extra_dev_deps << ['nokogiri', '~> 1.5']
  self.extra_dev_deps << ['minitest', '~> 2.0']
  self.extra_dev_deps << ['hoe-doofus', '~> 1.0']
  self.extra_dev_deps << ['hoe-gemspec', '~> 1.0']
  self.extra_dev_deps << ['hoe-git', '~> 1.0']
  self.extra_dev_deps << ['hoe-seattlerb', '~> 1.0']
end

namespace :mime do
  desc "Download the current MIME type registrations from IANA."
  task :iana, :save, :destination do |t, args|
    save_type = (args.save || :text).to_sym

    case save_type
    when :text, :both, :html
      nil
    else
      raise "Unknown save type provided. Must be one of text, both, or html."
    end

    destination = args.destination || "type-lists"

    require 'open-uri'
    require 'nokogiri'
    require 'cgi'

    class IANAParser
      include Comparable

      INDEX = %q(http://www.iana.org/assignments/media-types/)
      CONTACT_PEOPLE = %r{http://www.iana.org/assignments/contact-people.html?#(.*)}
      RFC_EDITOR = %r{http://www.rfc-editor.org/rfc/rfc(\d+).txt}
      IETF_RFC = %r{http://www.ietf.org/rfc/rfc(\d+).txt}
      IETF_RFC_TOOLS = %r{http://tools.ietf.org/html/rfc(\d+)}

      class << self
        def load_index
          @types ||= {}

          Nokogiri::HTML(open(INDEX) { |f| f.read }).xpath('//p/a').each do |tag|
            href_match = %r{^/assignments/media-types/(.+)/$}.match(tag['href'])
            next if href_match.nil?
            type = href_match.captures[0]
            @types[tag.content] = IANAParser.new(tag.content, type)
          end
        end

        attr_reader :types
      end

      def initialize(name, type)
        @name = name
        @type = type
        @url  = File.join(INDEX, @type)
      end

      attr_reader :name
      attr_reader :type
      attr_reader :url
      attr_reader :html

      def download(name = nil)
        @html = Nokogiri::HTML(open(name || @url) { |f| f.read })
      end

      def save_html
        File.open("#@name.html", "wb") { |w| w.write @html }
      end

      def <=>(o)
        self.name <=> o.name
      end

      def parse
        nodes = html.xpath("//table//table//tr")

        # How many <td> children does the first node have?
        node_count = nodes.first.children.select { |n| n.elem? }.size

        if node_count == 1
          # The title node doesn't have what we expect. Let's try it based
          # on the first real node.
          node_count = nodes.first.next.children.select { |n| n.elem? }.size
        end

        @mime_types = nodes.map do |node|
          next if node == nodes.first
          elems = node.children.select { |n| n.elem? }
          next if elems.size.zero?

          raise "size mismatch #{elems.size} != #{node_count}" if node_count != elems.size

          case elems.size
          when 3
            subtype_index = 1
            refnode_index = 2
          when 4
            subtype_index = 1
            refnode_index = 3
          else
            raise "Unknown element size."
          end

          subtype   = elems[subtype_index].content.chomp.strip
          refnodes  = elems[refnode_index].children.select { |n| n.elem? }.map { |ref|
            case ref['href']
            when CONTACT_PEOPLE
              tag = CGI::unescape($1).chomp.strip
              if tag == ref.content
            "[#{ref.content}]"
              else
            "[#{ref.content}=#{tag}]"
              end
            when RFC_EDITOR, IETF_RFC, IETF_RFC_TOOLS
          "RFC#$1"
            when %r{(https?://.*)}
          "{#{ref.content}=#$1}"
            else
              ref
            end
          }
          refs = refnodes.join(',')

      "#@type/#{subtype} 'IANA,#{refs}"
        end.compact

        @mime_types
      end

      def save_text
        File.open("#@name.txt", "wb") { |w| w.write @mime_types.join("\n") }
      end
    end

    puts "Downloading index of MIME types from #{IANAParser::INDEX}."
    IANAParser.load_index

    require 'fileutils'
    FileUtils.mkdir_p destination
    Dir.chdir destination do
      IANAParser.types.values.sort.each do |parser|
        next if parser.name == "example" or parser.name == "mime"
        puts "Downloading #{parser.name} from #{parser.url}"
        parser.download

        if :html == save_type || :both == save_type
          puts "Saving #{parser.name}.html"
          parser.save_html
        end

        puts "Parsing #{parser.name} HTML"
        parser.parse

        if :text == save_type || :both == save_type
          puts "Saving #{parser.name}.txt"
          parser.save_text
        end
      end
    end
  end

  desc "Shows known MIME type sources."
  task :mime_type_sources do
    puts <<-EOS
http://www.ltsw.se/knbase/internet/mime.htp
http://www.webmaster-toolkit.com/mime-types.shtml
http://plugindoc.mozdev.org/winmime.php
http://standards.freedesktop.org/shared-mime-info-spec/shared-mime-info-spec-latest.html  
http://www.feedforall.com/mime-types.htm
http://www.iana.org/assignments/media-types/
  EOS
  end
end

# vim: syntax=ruby
