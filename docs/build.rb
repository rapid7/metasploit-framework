require 'fileutils'
require 'uri'
require 'open3'
require 'optparse'
require_relative './navigation'

# Temporary build module to help migrate the Metasploit wiki https://github.com/rapid7/metasploit-framework/wiki into a format
# supported by Jekyll, as well as creating a hierarchical folder structure for nested documentation
#
# For now the doc folder only contains the key files for building the docs site and no content. The content is created on demand
# from the metasploit-framework wiki on each build
#
# In the future, the markdown files will be committed directly to the metasploit-framework directory, the wiki history will be
# merged with metasploit-framework, and the old wiki will no longer be updated.
module Build
  WIKI_PATH = 'metasploit-framework.wiki'.freeze
  PRODUCTION_BUILD_ARTIFACTS = '_site'.freeze

  # For now we Git clone the existing metasploit wiki and generate the Jekyll markdown files
  # for each build. This allows changes to be made to the existing wiki until it's migrated
  # into the main framework repo
  module Git
    def self.clone_wiki!
      unless File.exist?(WIKI_PATH)
        Build.run_command "git clone https://github.com/rapid7/metasploit-framework.wiki.git #{WIKI_PATH}", exception: true
      end

      Build.run_command "cd #{WIKI_PATH}; git pull", exception: true
    end
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
      raise "Unhandled paths #{missing_paths.join(', ')}" if missing_paths.any?

      each do |page|
        page_keys = page.keys
        allowed_keys = %i[path new_base_name nav_order title new_path folder children has_children parents]
        invalid_keys = page_keys - allowed_keys
        raise "#{page} had invalid keys #{invalid_keys.join(', ')}" if invalid_keys.any?
      end

      # Ensure unique folder names
      folder_titles = to_enum.select { |page| page[:folder] }.map { |page| page[:title] }
      duplicate_folder = folder_titles.tally.select { |_name, count| count > 1 }
      raise "Duplicate folder titles, will cause issues: #{duplicate_folder}" if duplicate_folder.any?

      # Ensure no folder titles match file titles
      page_titles = to_enum.reject { |page| page[:folder] }.map { |page| page[:title] }
      title_collisions = (folder_titles & page_titles).tally
      raise "Duplicate folder/page titles, will cause issues: #{title_collisions}" if title_collisions.any?

      # Ensure there are no files being migrated to multiple places
      page_paths = to_enum.reject { |page| page[:path] }.map { |page| page[:title] }
      duplicate_page_paths = page_paths.tally.select { |_name, count| count > 1 }
      raise "Duplicate paths, will cause issues: #{duplicate_page_paths}" if duplicate_page_paths.any?

      # Ensure new file paths are only alphanumeric and hyphenated
      new_paths = to_enum.map { |page| page[:new_path] }
      invalid_new_paths = new_paths.reject { |path| File.basename(path) =~ /^[a-zA-Z0-9_-]*\.md$/ }
      raise "Only alphanumeric and hyphenated file names required: #{invalid_new_paths}" if invalid_new_paths.any?
    end

    def available_paths
      Dir.glob("#{WIKI_PATH}/**/*{.md,.textile}", File::FNM_DOTMATCH)
    end

    def ignored_paths
      [
        '_Sidebar.md',
        'dev/_Sidebar.md',
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

    def without_prefix(prefix)
      proc { |value| value.gsub(/^#{prefix}/, '') }
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

      fix_github_username_links(new_markdown)
    end

    attr_reader :links

    protected

    def pages
      @config.enum_for(:each).map { |page| page }
    end

    # scans for absolute links to the old wiki such as 'https://github.com/rapid7/metasploit-framework/wiki/Metasploit-Web-Service'
    def extract_absolute_wiki_links(markdown)
      new_links = {}

      markdown.scan(%r{(https?://github.com/rapid7/metasploit-framework/wiki/([\w().%_-]+))}) do |full_match, old_path|
        full_match = full_match.gsub(/[).]+$/, '')
        old_path = URI.decode_www_form_component(old_path.gsub(/[).]+$/, ''))

        new_path = new_path_for(old_path)
        replacement = "{% link docs/#{new_path} %}"

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

    # Scans for substrings such as '[[Reference Sites|Git Reference Sites]]'
    def extract_relative_links(markdown)
      existing_links = @links
      new_links = {}
      markdown.scan(/(\[\[([\w_ '().:,-]+)(?:\|([\w_ '():,.-]+))?\]\])/) do |full_match, left, right|
        old_path = (right || left)
        new_path = new_path_for(old_path)
        if existing_links[full_match] && existing_links[full_match][:new_path] != new_path
          raise "Link for #{full_match} previously resolved to #{existing_links[full_match][:new_path]}, but now resolves to #{new_path}"
        end

        link_text = left
        replacement = "[#{link_text}]({% link docs/#{new_path} %})"

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

    def new_path_for(old_path)
      old_path = old_path.gsub(' ', '-')
      matched_pages = pages.select do |page|
        !page[:folder] &&
          page.fetch(:path).downcase.end_with?(old_path.downcase + '.md')
      end
      if matched_pages.empty?
        raise "Missing path for #{old_path}"
      end
      if matched_pages.count > 1
        raise "Duplicate paths for #{old_path}"
      end

      matched_pages.first.fetch(:new_path)
    end

    def fix_github_username_links(content)
      known_github_names = [
        '@0a2940',
        '@ChrisTuncer',
        '@TomSellers',
        '@asoto-r7',
        '@busterb',
        '@bwatters-r7',
        '@jbarnett-r7',
        '@jlee-r7',
        '@jmartin-r7',
        '@mcfakepants',
        '@Op3n4M3',
        '@gwillcox-r7',
        '@red0xff',
        '@mkienow-r7',
        '@pbarry-r7',
        '@schierlm',
        '@timwr',
        '@zerosteiner',
        '@zeroSteiner',
        '@harmj0y',
      ]
      ignored_tags = [
        '@harmj0yDescription',
        '@phpsessid',
        '@http_client',
        '@abstract',
        '@accepts_all_logins',
        '@addresses',
        '@aliases',
        '@channel',
        '@client',
        '@dep',
        '@handle',
        '@instance',
        '@param',
        '@pid',
        '@process',
        '@return',
        '@scanner',
        '@yieldparam',
        '@yieldreturn',
      ]

      # Replace any dangling github usernames, i.e. `@foo` - but not `[@foo](http://...)` or `email@example.com`
      content.gsub(/(?<![\[|\w])@[\w-]+/) do |username|
        if known_github_names.include? username
          "[#{username}](https://www.github.com/#{username.gsub('@', '')})"
        elsif ignored_tags.include? username
          username
        else
          raise "Unexpected username: '#{username}'"
        end
      end
    end
  end

  # Parses a wiki page and can add/remove/update a deprecation notice
  class WikiDeprecationText
    MARKDOWN_PREFIX = '#### Documentation Update:'.freeze
    private_constant :MARKDOWN_PREFIX

    def self.upsert(original_wiki_content, new_url:)
      message = "#{MARKDOWN_PREFIX} This is viewable at [#{new_url}](#{new_url})\n\n"
      "#{message}#{WikiDeprecationText.remove(original_wiki_content)}"
    end

    def self.remove(original_wiki_content)
      original_wiki_content.gsub(/#{MARKDOWN_PREFIX}.*$\s+/, '')
    end
  end

  # Converts Wiki markdown pages into a valid Jekyll format
  class WikiMigration
    # Implements two core components:
    # - Converts the existing Wiki markdown pages into a Jekyll format
    # - Optionally updates the existing Wiki markdown pages with a link to the new website location
    def run(config, options = {})
      config.validate!

      # Clean up new docs folder in preparation for regenerating it entirely from the latest wiki
      result_folder = File.join('.', 'docs')
      FileUtils.remove_dir(result_folder, true)
      FileUtils.mkdir(result_folder)

      link_corrector = link_corrector_for(config)
      config.each do |page|
        page_config = {
          layout: 'default',
          **page.slice(:title, :has_children, :nav_order),
          parent: (page[:parents][-1] || {})[:title]
        }.compact

        page_config[:has_children] = true if page[:has_children]
        preamble = <<~PREAMBLE
          ---
          #{page_config.map { |key, value| "#{key}: #{value.to_s.strip.inspect}" }.join("\n")}
          ---

        PREAMBLE

        new_path = File.join(result_folder, page[:new_path])
        FileUtils.mkdir_p(File.dirname(new_path))

        if page[:folder]
          new_docs_content = preamble.rstrip + "\n"
        else
          old_path = File.join(WIKI_PATH, page[:path])
          previous_content = File.read(old_path, encoding: Encoding::UTF_8)
          new_docs_content = preamble + WikiDeprecationText.remove(previous_content)
          new_docs_content = link_corrector.rerender(new_docs_content)

          # Update the existing Wiki with links to the new website
          if options[:update_existing_wiki]
            new_url = options[:update_existing_wiki][:new_website_url]
            if page[:new_path] != 'home.md'
              new_url += 'docs/' + page[:new_path].gsub('.md', '.html')
            end
            updated_wiki_content = WikiDeprecationText.upsert(previous_content, new_url: new_url)
            File.write(old_path, updated_wiki_content)
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
      config.each do |page|
        unless page[:folder]
          content = File.read(File.join(WIKI_PATH, page[:path]), encoding: Encoding::UTF_8)
          link_corrector.extract(content)
        end
      end

      link_corrector
    end
  end

  # Serve the production build at http://127.0.0.1:4000/metasploit-framework/
  class ProductionServer
    autoload :WEBrick, 'webrick'

    def self.run
      server = WEBrick::HTTPServer.new(
        {
          Port: 4000
        }
      )
      server.mount('/', WEBrick::HTTPServlet::FileHandler, PRODUCTION_BUILD_ARTIFACTS)
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
    puts command
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
        raise "command did not succeed, exit status #{wait_thread.value.exitstatus.inspect}"
      end
    end

    result
  end

  def self.run(options)
    Git.clone_wiki! unless options[:skip_wiki_pull]

    unless options[:skip_migration]
      config = Config.new(NAVIGATION_CONFIG)
      migrator = WikiMigration.new
      migrator.run(config, options)
    end

    if options[:production]
      FileUtils.remove_dir(PRODUCTION_BUILD_ARTIFACTS, true)
      run_command('JEKYLL_ENV=production jekyll build')

      if options[:serve]
        ProductionServer.run
      end
    elsif options[:serve]
      run_command('bundle exec jekyll serve --config _config.yml,_config_development.yml --incremental')
    end
  end
end

if $PROGRAM_NAME == __FILE__
  options = {}
  options_parser = OptionParser.new do |opts|
    opts.banner = "Usage: #{File.basename(__FILE__)} [options]"

    opts.on '-h', '--help', 'Help banner.' do
      return print(opts.help)
    end

    opts.on('--skip-wiki-pull', 'Skip pulling the Metasploit Wiki') do |skip_wiki_pull|
      options[:skip_wiki_pull] = skip_wiki_pull
    end

    opts.on('--skip-migration', 'Skip building the content') do |skip_migration|
      options[:skip_migration] = skip_migration
    end

    opts.on('--update-existing-wiki [website url]', 'Update the existing wiki with links to the new website location') do |new_website_url|
      new_website_url ||= 'https://docs.metasploit.com/'
      options[:update_existing_wiki] = {
        new_website_url: new_website_url
      }
    end

    opts.on('--production', 'Run a production build') do |production|
      options[:production] = production
    end

    opts.on('--serve', 'serve the docs site') do |serve|
      options[:serve] = serve
    end
  end
  options_parser.parse!

  Build.run(options)
end
