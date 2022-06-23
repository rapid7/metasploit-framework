require 'fileutils'
require 'uri'
require 'open3'
require 'optparse'
require_relative './navigation'

# Temporary build module to help migrate and build the Metasploit wiki https://github.com/rapid7/metasploit-framework/wiki into a format
# supported by Jekyll, as well as creating a hierarchical folder structure for nested documentation
#
# For now the doc folder only contains the key files for building the docs site and no content. The content is created on demand
# from the metasploit-framework wiki on each build
#
# In the future, the markdown files will be committed directly to the metasploit-framework directory, the wiki history will be
# merged with metasploit-framework, and the old wiki will no longer be updated.
module Build
  # The metasploit-framework.wiki files that are committed to Metasploit framework's repository
  WIKI_PATH = 'metasploit-framework.wiki'.freeze
  # A locally cloned version of https://github.com/rapid7/metasploit-framework/wiki
  OLD_WIKI_PATH = 'metasploit-framework.wiki.old'.freeze
  PRODUCTION_BUILD_ARTIFACTS = '_site'.freeze

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
        allowed_keys = %i[old_wiki_path path new_base_name nav_order title new_path folder children has_children parents]
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

    # Scans for Github wiki flavor links such as:
    #   '[[Relative Path]]'
    #   '[[Custom name|Relative Path]]'
    #   '[[Custom name|relative-path]]'
    #   '[[Custom name|./relative-path.md]]'
    def extract_relative_links(markdown)
      existing_links = @links
      new_links = {}
      markdown.scan(/(\[\[([\w\/_ '().:,-]+)(?:\|([\w\/_ '():,.-]+))?\]\])/) do |full_match, left, right|
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
          (File.basename(page[:path]).downcase == "#{File.basename(old_path)}.md".downcase ||
            File.basename(page[:path]).downcase == "#{File.basename(old_path)}".downcase)
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
          parent: (page[:parents][-1] || {})[:title],
          warning: "Do not modify this file directly. Please modify metasploit-framework/docs/metasploit-framework.wiki instead",
          old_path: page[:path] ? File.join(WIKI_PATH, page[:path]) : "none - folder automatically generated"
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
      FileUtils.remove_dir(PRODUCTION_BUILD_ARTIFACTS, true)
      run_command('JEKYLL_ENV=production bundle exec jekyll build')

      if options[:serve]
        ProductionServer.run
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
  options_parser.parse!

  Build.run(options)
end
