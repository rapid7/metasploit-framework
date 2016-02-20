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


      def list(content, list_type)
        if list_type == :unordered && content.scan(/<li>/).flatten.length > 15
          %Q|<p><div id=\"long_list\"><ul>#{content}<ul></div></p>|
        else
          %Q|<ul>#{content}</ul>|
        end
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
        HTML_TEMPLATE              = File.expand_path(File.join(Msf::Config.data_directory, 'markdown_doc', 'html_template.erb'))


        # Returns the module document in HTML form.
        #
        # @param items [Hash] Items to be documented.
        # @param kb [String] Additional information to be added in the doc.
        # @return [String] HTML.
        def get_md_content(items, kb)
          @md_template ||= lambda {
            template = ''
            File.open(TEMPLATE_PATH, 'rb') { |f| template = f.read }
            return template
          }.call
          md_to_html(ERB.new(@md_template).result(binding()), kb)
        end


        private


        # Returns the CSS code for the HTML document.
        #
        # @return [String]
        def load_css
          @css ||= lambda {
            data = ''
            File.open(CSS_BASE_PATH, 'rb') { |f| data = f.read }
            return data
          }.call
        end


        # Returns the HTML document.
        #
        # @param md [String] Markdown document.
        # @param kb [String] Additional information to add.
        # @return [String] HTML document.
        def md_to_html(md, kb)
          r = Redcarpet::Markdown.new(Redcarpet::Render::MsfMdHTML, fenced_code_blocks: true, no_intra_emphasis: true, escape_html: true)
          ERB.new(@html_template ||= lambda {
            html_template = ''
            File.open(HTML_TEMPLATE, 'rb') { |f| html_template = f.read }
            return html_template
          }.call).result(binding())
        end


        # Returns the markdown format for pull requests.
        #
        # @param pull_requests [Hash] Pull requests
        # @return [String]
        def normalize_pull_requests(pull_requests)
          if pull_requests.kind_of?(PullRequestFinder::Exception)
            error = pull_requests.message
            case error
            when /GITHUB_OAUTH_TOKEN/i
              error << " [See how]("
              error << "https://help.github.com/articles/creating-an-access-token-for-command-line-use/"
              error << ")"
            end
            return error
          end

          formatted_pr = []

          pull_requests.each_pair do |number, pr|
            formatted_pr << "* <a href=\"https://github.com/rapid7/metasploit-framework/pull/#{number}\">##{number}</a> - #{pr[:title]}"
          end

          formatted_pr * "\n"
        end


        # Returns the markdown format for module datastore options.
        #
        # @param mod_options [Hash] Datastore options
        # @return [String]
        def normalize_options(mod_options)
          required_options = []

          mod_options.each_pair do |name, props|
            if props.required && props.default.nil?
              required_options << "* #{name} - #{props.desc}"
            end
          end

          required_options * "\n"
        end


        # Returns the markdown format for module description.
        #
        # @param description [String] Module description.
        # @return [String]
        def normalize_description(description)
          Rex::Text.wordwrap(Rex::Text.compress(description))
        end


        # Returns the markdown format for module authors.
        #
        # @param authors [Array] Module Authors
        # @param authors [String] Module author
        # @return [String]
        def normalize_authors(authors)
          if authors.kind_of?(Array)
            authors.collect { |a| "* #{Rex::Text.html_encode(a)}" } * "\n"
          else
            authors
          end
        end


        # Returns the markdown format for module targets.
        #
        # @param targets [Array] Module targets.
        # @return [String]
        def normalize_targets(targets)
          targets.collect { |c| "* #{c.name}" } * "\n"
        end


        # Returns the markdown format for module references.
        #
        # @param refs [Array] Module references.
        # @return [String]
        def normalize_references(refs)
          refs.collect { |r| "* <a href=\"#{r}\">#{r}</a>" } * "\n"
        end


        # Returns the markdown format for module platforms.
        #
        # @param platforms [Array] Module platforms.
        # @param platforms [String] Module platform.
        # @return [String]
        def normalize_platforms(platforms)
          if platforms.kind_of?(Array)
            platforms.collect { |p| "* #{p}" } * "\n"
          else
            platforms
          end
        end


        # Returns the markdown format for module rank.
        #
        # @param rank [String] Module rank.
        # @return [String]
        def normalize_rank(rank)
          "[#{Msf::RankingName[rank].capitalize}](https://github.com/rapid7/metasploit-framework/wiki/Exploit-Ranking)"
        end


        # Returns a parsed ERB template.
        #
        # @param mod [Msf::Module] Metasploit module.
        # @param path [String] Template path.
        # @return [String]
        def load_template(mod, path)
          data = ''
          File.open(path, 'rb') { |f| data = f.read }
          ERB.new(data).result(binding())
        end


        # Returns a demo template suitable for the module. Currently supported templates:
        # BrowserExploitServer modules, HttpServer modules, local exploit modules, post
        # modules, payloads, auxiliary scanner modules.
        #
        # @param mod [Msf::Module] Metasploit module.
        # @return [String]
        def normalize_demo_output(mod)
          if mod.kind_of?(Msf::Exploit::Remote::BrowserExploitServer) && mod.shortname != 'browser_autopwn2'
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
