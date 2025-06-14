require 'fileutils'
require 'uri'
require 'open3'
require 'optparse'
require 'did_you_mean'
require 'kramdown'
require_relative './navigation'

# This build module was used to migrate the old Metasploit wiki https://github.com/rapid7/metasploit-framework/wiki into a format
# supported by Jekyll. Jekyll was chosen as it was written in Ruby, which should reduce the barrier to entry for contributions.
#
# The build script took the flatlist of markdown files from the wiki, and converted them into the hierarchical folder structure
# for nested documentation. This configuration is defined in `navigation.rb`
#
# In the future a different site generator could be used, but it should be possible to use this build script again to migrate to a new format
#
# For now the doc folder only contains the key files for building the docs site and no content. The content is created on demand
# from the `metasploit-framework.wiki` folder on each build
module Build
  # The metasploit-framework.wiki files that are committed to Metasploit framework's repository
  WIKI_PATH = 'metasploit-framework.wiki'.freeze
  # A locally cloned version of https://github.com/rapid7/metasploit-framework/wiki - should no longer be required for normal workflows
  OLD_WIKI_PATH = 'metasploit-framework.wiki.old'.freeze
  RELEASE_BUILD_ARTIFACTS = '_site'.freeze

  # For now we Git clone the existing metasploit wiki and generate the Jekyll markdown files
  # for each build. This allows changes to be made to the existing wiki until it's migrated
  # into the main framework repo
  module Git
    def self.clone_wiki!
      unless File.exist?(OLD_WIKI_PATH)
        Build.run_command "git clone https://github.com/rapid7/metasploit-framework.wiki.git #{OLD_WIKI_PATH}", exception: true
      end

      Build.run_command "cd #{OLD_WIKI_PATH}; git pull", exception: true
    end
  end

  class ConfigValidationError < StandardError
  end

  # Configuration for generating the new website hierarchy, from the existing metasploit-framework wiki
  class Config
    include Enumerable

    def initialize(config)
      @config = config
    end

    def validate!
      configured_paths = all_file_paths
      missing_paths = available_paths.map { |path| path.gsub("#{WIKI_PATH}/", '') } - ignored_paths - existing_docs - configured_paths
      raise ConfigValidationError, "Unhandled paths #{missing_paths.join(', ')} - add navigation entries to navigation.rb for these files" if missing_paths.any?

      each do |page|
        page_keys = page.keys
        allowed_keys = %i[old_wiki_path path new_base_name nav_order title new_path folder children has_children parents]
        invalid_keys = page_keys - allowed_keys

        suggestion = DidYouMean::SpellChecker.new(dictionary: allowed_keys).correct(invalid_keys[0]).first
        error = "#{page} had invalid keys #{invalid_keys.join(', ')}."
        error += " Did you mean #{suggestion}?" if suggestion

        raise ConfigValidationError, error  if invalid_keys.any?
      end

      # Ensure unique folder names
      folder_titles = to_enum.select { |page| page[:folder] }.map { |page| page[:title] }
      duplicate_folder = folder_titles.tally.select { |_name, count| count > 1 }
      raise ConfigValidationError, "Duplicate folder titles, will cause issues: #{duplicate_folder}" if duplicate_folder.any?

      # Ensure no folder titles match file titles
      page_titles = to_enum.reject { |page| page[:folder] }.map { |page| page[:title] }
      title_collisions = (folder_titles & page_titles).tally
      raise ConfigValidationError, "Duplicate folder/page titles, will cause issues: #{title_collisions}" if title_collisions.any?

      # Ensure there are no files being migrated to multiple places
      page_paths = to_enum.reject { |page| page[:path] }.map { |page| page[:title] }
      duplicate_page_paths = page_paths.tally.select { |_name, count| count > 1 }
      raise ConfigValidationError, "Duplicate paths, will cause issues: #{duplicate_page_paths}" if duplicate_page_paths.any?

      # Ensure new file paths are only alphanumeric and hyphenated
      new_paths = to_enum.map { |page| page[:new_path] }
      invalid_new_paths = new_paths.reject { |path| File.basename(path) =~ /^[a-zA-Z0-9_-]*\.md$/ }
      raise ConfigValidationError, "Only alphanumeric and hyphenated file names required: #{invalid_new_paths}" if invalid_new_paths.any?
    end

    def available_paths
      Dir.glob("#{WIKI_PATH}/**/*{.md,.textile}", File::FNM_DOTMATCH)
    end

    def ignored_paths
      [
      ]
    end

    def existing_docs
      existing_docs = Dir.glob('docs/**/*', File::FNM_DOTMATCH)
      existing_docs
    end

    def each(&block)
      config.each do |parent|
        recurse(with_metadata(parent), &block)
      end
    end

    def all_file_paths
      to_enum.map { |item| item[:path] }.to_a
    end

    protected

    # depth first traversal
    def recurse(parent_with_metadata, &block)
      block.call(parent_with_metadata)
      parent_with_metadata[:children].to_a.each do |child|
        child_with_metadata = with_metadata(child, parents: parent_with_metadata[:parents] + [parent_with_metadata])
        recurse(child_with_metadata, &block)
      end
    end

    def with_metadata(child, parents: [])
      child = child.clone

      if child[:folder]
        parent_folders = parents.map { |page| page[:folder] }
        child[:new_path] = File.join(*parent_folders, child[:folder], 'index.md')
      else
        path = child[:path]
        base_name = child[:new_base_name] || File.basename(path)

        # title calculation
        computed_title = File.basename(base_name, '.md').gsub('-', ' ')
        if child[:title].is_a?(Proc)
          child[:title] = child[:title].call(computed_title)
        else
          child[:title] ||= computed_title
        end

        parent_folders = parents.map { |page| page[:folder] }
        child[:new_path] = File.join(*parent_folders, base_name.downcase)
      end

      child[:parents] = parents
      child[:has_children] = true if child[:children].to_a.any?

      child
    end

    attr_reader :config
  end

  # Extracts markdown links from https://github.com/rapid7/metasploit-framework/wiki into a Jekyll format
  # Additionally corrects links to Github
  class LinkCorrector
    def initialize(config)
      @config = config
      @links = {}
    end

    def syntax_errors_for(markdown)
      MarkdownLinkSyntaxVerifier.errors_for(markdown)
    end

    def extract(markdown)
      extracted_absolute_wiki_links = extract_absolute_wiki_links(markdown)
      @links = @links.merge(extracted_absolute_wiki_links)

      extracted_relative_links = extract_relative_links(markdown)
      @links = @links.merge(extracted_relative_links)

      @links
    end

    def rerender(markdown)
      links ||= @links

      new_markdown = markdown.clone
      links.each_value do |link|
        new_markdown.gsub!(link[:full_match], link[:replacement])
      end

      new_markdown
    end

    attr_reader :links

    protected

    def pages
      @config.enum_for(:each).map { |page| page }
    end

    # scans for absolute links to the old wiki such as 'https://docs.metasploit.com/docs/using-metasploit/advanced/metasploit-web-service.html'
    def extract_absolute_wiki_links(markdown)
      new_links = {}

      markdown.scan(%r{(https?://github.com/rapid7/metasploit-framework/wiki/([\w().%_#-]+))}) do |full_match, old_path|
        full_match = full_match.gsub(/[).]+$/, '')
        old_path = URI.decode_www_form_component(old_path.gsub(/[).]+$/, ''))

        begin
          old_path_anchor = URI.parse(old_path).fragment
        rescue URI::InvalidURIError
          old_path_anchor = nil
        end

        new_path = new_path_for(old_path, old_path_anchor)
        replacement = "{% link docs/#{new_path} %}#{old_path_anchor ? "##{old_path_anchor}" : ""}"

        link = {
          full_match: full_match,
          type: :absolute,
          new_path: new_path,
          replacement: replacement
        }

        new_links[full_match] = link
      end

      new_links
    end

    # Scans for Github wiki flavor links such as:
    #   '[[Relative Path]]'
    #   '[[Custom name|Relative Path]]'
    #   '[[Custom name|relative-path]]'
    #   '[[Custom name|./relative-path.md]]'
    #   '[[Custom name|./relative-path.md#section-anchor-to-link-to]]'
    # Note that the page target resource file is validated for existence at build time - but the section anchors are not
    def extract_relative_links(markdown)
      existing_links = @links
      new_links = {}

      markdown.scan(/(\[\[([\w\/_ '().:,-]+)(?:\|([\w\/_ '():,.#-]+))?\]\])/) do |full_match, left, right|
        old_path = (right || left)
        begin
          old_path_anchor = URI.parse(old_path).fragment
        rescue URI::InvalidURIError
          old_path_anchor = nil
        end
        new_path = new_path_for(old_path, old_path_anchor)
        if existing_links[full_match] && existing_links[full_match][:new_path] != new_path
          raise "Link for #{full_match} previously resolved to #{existing_links[full_match][:new_path]}, but now resolves to #{new_path}"
        end

        link_text = left
        replacement = "[#{link_text}]({% link docs/#{new_path} %}#{old_path_anchor ? "##{old_path_anchor}" : ""})"

        link = {
          full_match: full_match,
          type: :relative,
          left: left,
          right: right,
          new_path: new_path,
          replacement: replacement
        }

        new_links[full_match] = link
      end

      new_links
    end

    def new_path_for(old_path, old_path_anchor)
      # Strip out any leading `./` or `/` before the relative path.
      # This is needed for our later code that does additional filtering for
      # potential ambiguity with absolute paths since those comparisons occur
      # against filenames without the leading ./ and / parts.
      old_path = old_path.gsub(/^[.\/]+/, '')

      # Replace any spaces in the file name with - separators, then
      # make replace anchors with an empty string.
      old_path = old_path.gsub(' ', '-').gsub("##{old_path_anchor}", '')

      matched_pages = pages.select do |page|
        !page[:folder] &&
          (File.basename(page[:path]).downcase == "#{File.basename(old_path)}.md".downcase ||
            File.basename(page[:path]).downcase == "#{File.basename(old_path)}".downcase)
      end
      if matched_pages.empty?
        raise "Link not found: #{old_path}"
      end
      # Additional filter for absolute paths if there's potential ambiguity
      if matched_pages.count > 1
        refined_pages = matched_pages.select do |page|
          !page[:folder] &&
            (page[:path].downcase == "#{old_path}.md".downcase ||
              page[:path].downcase == old_path.downcase)
        end

        if refined_pages.count != 1
          page_paths = matched_pages.map { |page| page[:path] }
          raise "Duplicate paths for #{old_path} - possible page paths found: #{page_paths}"
        end

        matched_pages = refined_pages
      end

      matched_pages.first.fetch(:new_path)
    end
  end

  # Verifies that markdown links are not relative. Instead the Github wiki flavored syntax should be used.
  #
  # Example bad: `[Human readable text](./some-documentation-link)`
  # Example good: `[[Human readable text|./some-documentation-link]]`
  class MarkdownLinkSyntaxVerifier
    # Detects the usage of bad syntax and returns an array of detected errors
    #
    # @param [String] markdown The markdown
    # @return [Array<String>] An array of human readable errors that should be resolved
    def self.errors_for(markdown)
      document = Kramdown::Document.new(markdown)
      document.to_validated_wiki_page
      warnings = document.warnings.select { |warning| warning.start_with?(Kramdown::Converter::ValidatedWikiPage::WARNING_PREFIX) }
      warnings
    end

    # Implementation detail: There doesn't seem to be a generic AST visitor pattern library for Ruby; We instead implement
    # Kramdown's Markdown to HTML Converter API, override the link converter method, and warn on any invalid links that are identified.
    # The {MarkdownLinkVerifier} will ignore the HTML result, and return any detected errors instead.
    #
    # https://kramdown.gettalong.org/rdoc/Kramdown/Converter/Html.html
    class Kramdown::Converter::ValidatedWikiPage < Kramdown::Converter::Html
      WARNING_PREFIX = '[WikiLinkValidation]'

      def convert_a(el, indent)
        link_href = el.attr['href']
        if relative_link?(link_href)
          link_text = el.children.map { |child| convert(child) }.join
          warning "Invalid docs link syntax found on line #{el.options[:location]}: Invalid relative link #{link_href} found. Please use the syntax [[#{link_text}|#{link_href}]] instead"
        end

        if absolute_docs_link?(link_href)
          begin
            example_path = ".#{URI.parse(link_href).path}"
          rescue URI::InvalidURIError
            example_path = "./path-to-markdown-file"
          end

          link_text = el.children.map { |child| convert(child) }.join
          warning "Invalid docs link syntax found on line #{el.options[:location]}: Invalid absolute link #{link_href} found. Please use relative links instead, i.e. [[#{link_text}|#{example_path}]] instead"
        end

        super
      end

      private

      def warning(text)
        super "#{WARNING_PREFIX} #{text}"
      end

      def relative_link?(link_path)
        !(link_path.start_with?('http:') || link_path.start_with?('https:') || link_path.start_with?('mailto:') || link_path.start_with?('#'))
      end

      # @return [TrueClass, FalseClass] True if the link is to a Metasploit docs page that isn't either the root home page or the API site, otherwise false
      def absolute_docs_link?(link_path)
        link_path.include?('docs.metasploit.com') && !link_path.include?('docs.metasploit.com/api') && !(link_path == 'https://docs.metasploit.com/')
      end
    end
  end

  # Parses a wiki page and can add/remove/update a deprecation notice
  class WikiDeprecationText
    MAINTAINER_MESSAGE_PREFIX = "<!-- Maintainers: "
    private_constant :MAINTAINER_MESSAGE_PREFIX

    USER_MESSAGE_PREFIX = '**Documentation Update:'.freeze
    private_constant :USER_MESSAGE_PREFIX

    def self.upsert(original_wiki_content, old_path:, new_url:)
      history_link = old_path.include?("#{WIKI_PATH}/Home.md") ? './Home/_history' : './_history'
      maintainer_message = "#{MAINTAINER_MESSAGE_PREFIX} Please do not modify this file directly, create a pull request instead -->\n\n"
      user_message = "#{USER_MESSAGE_PREFIX} This Wiki page should be viewable at [#{new_url}](#{new_url}). Or if it is no longer available, see this page's [previous history](#{history_link})**\n\n"
      deprecation_text = maintainer_message + user_message
      "#{deprecation_text}"
    end

    def self.remove(original_wiki_content)
      original_wiki_content
        .gsub(/^#{Regexp.escape(MAINTAINER_MESSAGE_PREFIX)}.*$\s+/, '')
        .gsub(/^#{Regexp.escape(USER_MESSAGE_PREFIX)}.*$\s+/, '')
    end
  end

  # Converts Wiki markdown pages into a valid Jekyll format
  class WikiMigration
    # Implements two core components:
    # - Converts the existing Wiki markdown pages into a Jekyll format
    # - Optionally updates the existing Wiki markdown pages with a link to the new website location
    def run(config, options = {})
      begin
        config.validate!
      rescue
        puts "[!] Validation failed. Please verify navigation.rb is valid, as well as the markdown file"
        raise
      end

      # Clean up new docs folder in preparation for regenerating it entirely from the latest wiki
      result_folder = File.join('.', 'docs')
      FileUtils.remove_dir(result_folder, true)
      FileUtils.mkdir(result_folder)

      link_corrector = link_corrector_for(config)
      config.each do |page|
        page_config = {
          layout: 'default',
          **page.slice(:title, :has_children, :nav_order),
          parent: (page[:parents][-1] || {})[:title],
          warning: "Do not modify this file directly. Please modify metasploit-framework/docs/metasploit-framework.wiki instead",
          old_path: page[:path] ? File.join(WIKI_PATH, page[:path]) : "none - folder automatically generated",
          has_content: !page[:path].nil?
        }.compact

        page_config[:has_children] = true if page[:has_children]
        preamble = <<~PREAMBLE
          ---
          #{page_config.map { |key, value| "#{key}: #{value.to_s.strip.inspect}" }.join("\n")}
          ---

        PREAMBLE

        new_path = File.join(result_folder, page[:new_path])
        FileUtils.mkdir_p(File.dirname(new_path))

        if page[:folder] && page[:path].nil?
          new_docs_content = preamble.rstrip + "\n"
        else
          old_path = File.join(WIKI_PATH, page[:path])
          previous_content = File.read(old_path, encoding: Encoding::UTF_8)
          new_docs_content = preamble + WikiDeprecationText.remove(previous_content)
          new_docs_content = link_corrector.rerender(new_docs_content)

          # Update the old Wiki with links to the new website
          if options[:update_wiki_deprecation_notice]
            new_url = options[:update_wiki_deprecation_notice][:new_website_url]
            if page[:new_path] != 'home.md'
              new_url += 'docs/' + page[:new_path].gsub('.md', '.html')
            end
            updated_wiki_content = WikiDeprecationText.upsert(previous_content, old_path: old_path, new_url: new_url)
            old_wiki_path = File.join(WIKI_PATH, page[:path])
            File.write(old_wiki_path, updated_wiki_content, mode: 'w', encoding: Encoding::UTF_8)
          end
        end

        File.write(new_path, new_docs_content, mode: 'w', encoding: Encoding::UTF_8)
      end

      # Now that the docs folder is created, time to move the home.md file out
      FileUtils.mv('docs/home.md', 'index.md')
    end

    protected

    def link_corrector_for(config)
      link_corrector = LinkCorrector.new(config)
      errors = []
      config.each do |page|
        unless page[:path].nil?
          content = File.read(File.join(WIKI_PATH, page[:path]), encoding: Encoding::UTF_8)
          syntax_errors = link_corrector.syntax_errors_for(content)
          errors << { path: page[:path], messages: syntax_errors } if syntax_errors.any?

          link_corrector.extract(content)
        end
      end

      if errors.any?
        errors.each do |error|
          $stderr.puts "[!] Error #{File.join(WIKI_PATH, error[:path])}:\n#{error[:messages].map { |message| "\t- #{message}\n" }.join}"
        end

        raise "Errors found in markdown syntax"
      end

      link_corrector
    end
  end

  # Serve the release build at http://127.0.0.1:4000/metasploit-framework/
  class ReleaseBuildServer
    autoload :WEBrick, 'webrick'

    def self.run
      server = WEBrick::HTTPServer.new(
        {
          Port: 4000
        }
      )
      server.mount('/', WEBrick::HTTPServlet::FileHandler, RELEASE_BUILD_ARTIFACTS)
      trap('INT') do
        server.shutdown
      rescue StandardError
        nil
      end
      server.start
    ensure
      server.shutdown
    end
  end

  def self.run_command(command, exception: true)
    puts "[*] #{command}"
    result = ''
    ::Open3.popen2e(
      { 'BUNDLE_GEMFILE' => File.join(Dir.pwd, 'Gemfile') },
      '/bin/bash', '--login', '-c', command
    ) do |stdin, stdout_and_stderr, wait_thread|
      stdin.close_write

      while wait_thread.alive?
        ready = IO.select([stdout_and_stderr], nil, nil, 1)

        next unless ready
        reads, _writes, _errors = ready

        reads.to_a.each do |io|
          data = io.read_nonblock(1024)
          puts data
          result += data
        rescue EOFError, Errno::EAGAIN
          # noop
        end
      end

      if !wait_thread.value.success? && exception
        raise "command #{command.inspect} did not succeed, exit status #{wait_thread.value.exitstatus.inspect}"
      end
    end

    result
  end

  def self.run(options)
    Git.clone_wiki! if options[:wiki_pull]

    # Create a new branch based on the commits from https://github.com/rapid7/metasploit-framework/wiki to move
    # Wiki files into the metasploit-framework repo
    if options[:create_wiki_to_framework_migration_branch]
      starting_branch = run_command("git rev-parse --abbrev-ref HEAD").chomp
      new_wiki_branch_name = "move-all-docs-into-folder"
      new_framework_branch_name = "merge-metasploit-framework-wiki-into-metasploit-framework"

      begin
        # Create a new folder and branch in the old metasploit wiki for where we'd like it to be inside of the metasploit-framework repo
        Dir.chdir(OLD_WIKI_PATH) do
          # Reset the repo back
          run_command("git checkout master", exception: false)
          run_command("git reset HEAD --hard", exception: false)
          run_command("rm -rf metasploit-framework.wiki", exception: false)

          # Create a new folder to move the wiki contents into
          FileUtils.mkdir_p("metasploit-framework.wiki")
          run_command("mv *[^metasploit-framework.wiki]* metasploit-framework.wiki", exception: false)

          # Create a new branch + commit
          run_command("git branch -D #{new_wiki_branch_name}", exception: false)
          run_command("git checkout -b #{new_wiki_branch_name}")
          run_command("git add metasploit-framework.wiki")
          run_command("git commit -am 'Put markdown files into new folder metasploit-framework.wiki in preparation for migration'")
        end

        # Create a new branch that can be used to create a pull request
        run_command("git branch -D #{new_framework_branch_name}", exception: false)
        run_command("git checkout -b #{new_framework_branch_name}")
        run_command("git remote remove wiki", exception: false)
        run_command("git remote add -f wiki #{File.join(Dir.pwd, OLD_WIKI_PATH)}", exception: false)
        # run_command("git remote update wiki")
        run_command("git merge -m 'Migrate docs from https://github.com/rapid7/metasploit-framework/wiki to main repository' wiki/#{new_wiki_branch_name} --allow-unrelated-histories")

        puts "new branch #{new_framework_branch_name} successfully created"
      ensure
        run_command("git checkout #{starting_branch}")
      end
    end

    if options[:copy_old_wiki]
      FileUtils.copy_entry(OLD_WIKI_PATH, WIKI_PATH, preserve = false, dereference_root = false, remove_destination = true)
      # Remove any deprecation text that might be present after copying the old wiki
      Dir.glob(File.join(WIKI_PATH, '**', '*.md')) do |path|
        previous_content = File.read(path, encoding: Encoding::UTF_8)
        new_content = WikiDeprecationText.remove(previous_content)

        File.write(path, new_content, mode: 'w', encoding: Encoding::UTF_8)
      end
    end

    unless options[:build_content]
      config = Config.new(NAVIGATION_CONFIG)
      migrator = WikiMigration.new
      migrator.run(config, options)
    end

    if options[:production]
      FileUtils.remove_dir(RELEASE_BUILD_ARTIFACTS, true)
      run_command('JEKYLL_ENV=production bundle exec jekyll build')

      if options[:serve]
        ReleaseBuildServer.run
      end
    elsif options[:staging]
      FileUtils.remove_dir(RELEASE_BUILD_ARTIFACTS, true)
      run_command('JEKYLL_ENV=production bundle exec jekyll build --config _config.yml,_config_staging.yml')

      if options[:serve]
        ReleaseBuildServer.run
      end
    elsif options[:serve]
      run_command('bundle exec jekyll serve --config _config.yml,_config_development.yml --incremental')
    end
  end
end

if $PROGRAM_NAME == __FILE__
  options = {
    copy_old_wiki: false,
    wiki_pull: false
  }
  options_parser = OptionParser.new do |opts|
    opts.banner = "Usage: #{File.basename(__FILE__)} [options]"

    opts.on '-h', '--help', 'Help banner.' do
      return print(opts.help)
    end

    opts.on('--production', 'Run a production build') do |production|
      options[:production] = production
    end

    opts.on('--staging', 'Run a staging build for deploying to gh-pages') do |staging|
      options[:staging] = staging
    end

    opts.on('--serve', 'serve the docs site') do |serve|
      options[:serve] = serve
    end

    opts.on('--[no]-copy-old-wiki [FLAG]', TrueClass, 'Copy the content from the old wiki to the new local wiki folder') do |copy_old_wiki|
      options[:copy_old_wiki] = copy_old_wiki
    end

    opts.on('--[no-]-wiki-pull', FalseClass, 'Pull the Metasploit Wiki') do |wiki_pull|
      options[:wiki_pull] = wiki_pull
    end

    opts.on('--update-wiki-deprecation-notice [WEBSITE_URL]', 'Updates the old wiki deprecation notes') do |new_website_url|
      new_website_url ||= 'https://docs.metasploit.com/'
      options[:update_wiki_deprecation_notice] = {
        new_website_url: new_website_url
      }
    end

    opts.on('--create-wiki-to-framework-migration-branch') do
      options[:create_wiki_to_framework_migration_branch] = true
    end
  end
  if ARGV.length == 0
    puts options_parser.help
    exit 1
  end
  options_parser.parse!

  Build.run(options)
end
