require 'redcarpet'
require 'erb'

module Redcarpet
  module Render
    class MsfMdHTML < Redcarpet::Render::HTML
      def block_code(code, language)
        "<pre>" \
          "<code>#{code}</code>" \
        "</pre>"
      end
    end
  end
end

module Msf
  module Util
    module DocumentGenerator
      class DocumentNormalizer

        CSS_BASE_PATH              = File.expand_path(File.join(Msf::Config.data_directory, 'markdown_doc', 'markdown.css'))
        TEMPLATE_PATH              = File.expand_path(File.join(Msf::Config.data_directory, 'markdown_doc', 'default_template.erb'))
        BES_DEMO_TEMPLATE          = File.expand_path(File.join(Msf::Config.data_directory, 'markdown_doc', 'bes_demo_template.erb'))
        HTTPSERVER_DEMO_TEMPLATE   = File.expand_path(File.join(Msf::Config.data_directory, 'markdown_doc', 'httpserver_demo_template.erb'))
        GENERIC_DEMO_TEMPLATE      = File.expand_path(File.join(Msf::Config.data_directory, 'markdown_doc', 'generic_demo_template.erb'))
        LOCALEXPLOIT_DEMO_TEMPLATE = File.expand_path(File.join(Msf::Config.data_directory, 'markdown_doc', 'localexploit_demo_template.erb'))
        POST_DEMO_TEMPLATE         = File.expand_path(File.join(Msf::Config.data_directory, 'markdown_doc', 'post_demo_template.erb'))
        PAYLOAD_TEMPLATE           = File.expand_path(File.join(Msf::Config.data_directory, 'markdown_doc', 'payload_demo_template.erb'))
        AUXILIARY_SCANNER_TEMPLATE = File.expand_path(File.join(Msf::Config.data_directory, 'markdown_doc', 'auxiliary_scanner_template.erb'))

        def get_md_content(items)
          @md_template ||= lambda {
            template = ''
            File.open(TEMPLATE_PATH, 'rb') { |f| template = f.read }
            return template
          }.call
          md_to_html(ERB.new(@md_template).result(binding()))
        end

        private

        def load_css
          @css ||= lambda {
            data = ''
            File.open(CSS_BASE_PATH, 'rb') { |f| data = f.read }
            return data
          }.call
        end

        def md_to_html(md)
          r = Redcarpet::Markdown.new(Redcarpet::Render::MsfMdHTML, fenced_code_blocks: true) 
          %Q|
          <html>
          <head>
          <style>
          #{load_css}
          </style>
          </head>
          <body>
          #{r.render(md)}
          </body>
          </html>
          |
        end

        def normalize_pull_requests(pull_requests)
          if pull_requests.kind_of?(PullRequestFinder::Exception)
            error = Rex::Text.html_encode(pull_requests.message)
            return error
          end

          formatted_pr = []

          pull_requests.each_pair do |number, pr|
            formatted_pr << "* <a href=\"https://github.com/rapid7/metasploit-framework/pull/#{number}\">##{number}</a> - #{pr[:title]}"
          end

          formatted_pr * "\n"
        end

        def normalize_options(mod_options)
          required_options = []

          mod_options.each_pair do |name, props|
            if props.required && props.default.nil?
              required_options << "* #{name} - #{props.desc}"
            end
          end

          required_options * "\n"
        end

        def normalize_description(description)
          Rex::Text.wordwrap(Rex::Text.compress(description))
        end

        def normalize_authors(authors)
          if authors.kind_of?(Array)
            authors.collect { |a| "* #{Rex::Text.html_encode(a)}" } * "\n"
          else
            Rex::Text.html_encode(authors)
          end
        end

        def normalize_targets(targets)
          targets.collect { |c| "* #{c.name}" } * "\n"
        end

        def normalize_references(refs)
          refs.collect { |r| "* <a href=\"#{r}\">#{r}</a>" } * "\n"
        end

        def normalize_platforms(platforms)
          if platforms.kind_of?(Array)
            platforms.collect { |p| "* #{p}" } * "\n"
          else
            platforms
          end
        end

        def normalize_rank(rank)
          "[#{Msf::RankingName[rank].capitalize}](https://github.com/rapid7/metasploit-framework/wiki/Exploit-Ranking)"
        end

        def load_template(mod, path)
          data = ''
          File.open(path, 'rb') { |f| data = f.read }
          ERB.new(data).result(binding())
        end

        def normalize_demo_output(mod)
          if mod.kind_of?(Msf::Exploit::Remote::BrowserExploitServer)
            load_template(mod, BES_DEMO_TEMPLATE)
          elsif mod.kind_of?(Msf::Exploit::Remote::HttpServer)
            load_template(mod, HTTPSERVER_DEMO_TEMPLATE)
          elsif mod.kind_of?(Msf::Exploit::Local)
            load_template(mod, LOCALEXPLOIT_DEMO_TEMPLATE)
          elsif mod.kind_of?(Msf::Post)
            load_template(mod, POST_DEMO_TEMPLATE)
          elsif mod.kind_of?(Msf::Payload)
            load_template(mod, PAYLOAD_TEMPLATE)
          elsif mod.kind_of?(Msf::Auxiliary::Scanner)
            load_template(mod, AUXILIARY_SCANNER_TEMPLATE)
          else
            load_template(mod, GENERIC_DEMO_TEMPLATE)
          end
        end

      end
    end
  end
end