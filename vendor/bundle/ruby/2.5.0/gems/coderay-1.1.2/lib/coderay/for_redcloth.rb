module CodeRay
  
  # A little hack to enable CodeRay highlighting in RedCloth.
  # 
  # Usage:
  #  require 'coderay'
  #  require 'coderay/for_redcloth'
  #  RedCloth.new('@[ruby]puts "Hello, World!"@').to_html
  # 
  # Make sure you have RedCloth 4.0.3 activated, for example by calling
  #  require 'rubygems'
  # before RedCloth is loaded and before calling CodeRay.for_redcloth.
  module ForRedCloth
    
    def self.install
      gem 'RedCloth', '>= 4.0.3' if defined? gem
      require 'redcloth'
      unless RedCloth::VERSION.to_s >= '4.0.3'
        if defined? gem
          raise 'CodeRay.for_redcloth needs RedCloth version 4.0.3 or later. ' +
            "You have #{RedCloth::VERSION}. Please gem install RedCloth."
        else
          $".delete 'redcloth.rb'  # sorry, but it works
          require 'rubygems'
          return install  # retry
        end
      end
      unless RedCloth::VERSION.to_s >= '4.2.2'
        warn 'CodeRay.for_redcloth works best with RedCloth version 4.2.2 or later.'
      end
      RedCloth::TextileDoc.send :include, ForRedCloth::TextileDoc
      RedCloth::Formatters::HTML.module_eval do
        def unescape(html)  # :nodoc:
          replacements = {
            '&amp;' => '&',
            '&quot;' => '"',
            '&gt;' => '>',
            '&lt;' => '<',
          }
          html.gsub(/&(?:amp|quot|[gl]t);/) { |entity| replacements[entity] }
        end
        undef code, bc_open, bc_close, escape_pre
        def code(opts)  # :nodoc:
          opts[:block] = true
          if !opts[:lang] && RedCloth::VERSION.to_s >= '4.2.0'
            # simulating pre-4.2 behavior
            if opts[:text].sub!(/\A\[(\w+)\]/, '')
              if CodeRay::Scanners[$1].lang == :text
                opts[:text] = $& + opts[:text]
              else
                opts[:lang] = $1
              end
            end
          end
          if opts[:lang] && !filter_coderay
            require 'coderay'
            @in_bc ||= nil
            format = @in_bc ? :div : :span
            opts[:text] = unescape(opts[:text]) unless @in_bc
            highlighted_code = CodeRay.encode opts[:text], opts[:lang], format
            highlighted_code.sub!(/\A<(span|div)/) { |m| m + pba(@in_bc || opts) }
            highlighted_code
          else
            "<code#{pba(opts)}>#{opts[:text]}</code>"
          end
        end
        def bc_open(opts)  # :nodoc:
          opts[:block] = true
          @in_bc = opts
          opts[:lang] ? '' : "<pre#{pba(opts)}>"
        end
        def bc_close(opts)  # :nodoc:
          opts = @in_bc
          @in_bc = nil
          opts[:lang] ? '' : "</pre>\n"
        end
        def escape_pre(text)  # :nodoc:
          if @in_bc ||= nil
            text
          else
            html_esc(text, :html_escape_preformatted)
          end
        end
      end
    end

    module TextileDoc  # :nodoc:
      attr_accessor :filter_coderay
    end
    
  end
  
end

CodeRay::ForRedCloth.install