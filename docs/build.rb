require 'fileutils'
require 'uri'
require 'open3'
require 'optparse'

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
  PRODUCTION_BUILD_ARTIFACTS = '_site'

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

  # Configuration for generating the new website hierachy, from the existing metasploit-framework wiki
  class Config
    include Enumerable
    def initialize
      @config = [
        {
          path: 'Home.md',
          nav_order: 1
        },
        {
          path: 'Code-Of-Conduct.md',
          nav_order: 2
        },
        {
          title: 'Using Metasploit',
          folder: 'using-metasploit',
          nav_order: 3,
          children: [
            {
              title: 'Getting Started',
              folder: 'getting-started',
              nav_order: 1,
              children: [
                {
                  path: 'Nightly-Installers.md',
                  nav_order: 1
                },
                {
                  path: 'Reporting-a-Bug.md',
                  nav_order: 4
                },
              ]
            },
            {
              title: 'Basics',
              folder: 'basics',
              nav_order: 2,
              children: [
                {
                  path: 'Using-Metasploit.md',
                  title: 'Running modules',
                  nav_order: 2
                },
                {
                  path: 'How-to-use-msfvenom.md',
                  nav_order: 3
                },
                {
                  path: 'How-to-use-a-Metasploit-module-appropriately.md'
                },
                {
                  path: 'How-payloads-work.md'
                },
                {
                  path: 'Module-Documentation.md'
                },
                {
                  path: 'How-to-use-a-reverse-shell-in-Metasploit.md'
                },
              ]
            },
            {
              title: 'Intermediate',
              folder: 'intermediate',
              nav_order: 3,
              children: [
                {
                  path: 'Evading-Anti-Virus.md'
                },
                {
                  path: 'Payload-UUID.md'
                },
                {
                  path: 'Running-Private-Modules.md'
                },
                {
                  path: 'Exploit-Ranking.md'
                },
                {
                  path: 'Hashes-and-Password-Cracking.md'
                },
                {
                  path: 'msfdb:-Database-Features-&-How-to-Set-up-a-Database-for-Metasploit.md',
                  new_base_name: 'Metasploit-Database-Support.md',
                  title: 'Database Support'
                },
              ]
            },
            {
              title: 'Advanced',
              folder: 'advanced',
              nav_order: 4,
              children: [
                {
                  path: 'Metasploit-Web-Service.md'
                },
                {
                  title: 'Meterpreter',
                  folder: 'meterpreter',
                  children: [
                    {
                      path: 'Meterpreter.md',
                      title: 'Overview',
                      nav_order: 1
                    },
                    {
                      path: 'Meterpreter-Transport-Control.md',
                      title: without_prefix('Meterpreter ')
                    },
                    {
                      path: 'Meterpreter-Unicode-Support.md',
                      title: without_prefix('Meterpreter ')
                    },
                    {
                      path: 'Meterpreter-Paranoid-Mode.md',
                      title: without_prefix('Meterpreter ')
                    },
                    {
                      path: 'The-ins-and-outs-of-HTTP-and-HTTPS-communications-in-Meterpreter-and-Metasploit-Stagers.md'
                    },
                    {
                      path: 'Meterpreter-Timeout-Control.md',
                      title: without_prefix('Meterpreter ')
                    },
                    {
                      path: 'Meterpreter-Wishlist.md',
                      title: without_prefix('Meterpreter ')
                    },
                    {
                      path: 'Meterpreter-Sleep-Control.md',
                      title: without_prefix('Meterpreter ')
                    },
                    {
                      path: 'Meterpreter-Configuration.md',
                      title: without_prefix('Meterpreter ')
                    },
                    {
                      path: 'Meterpreter-Reliable-Network-Communication.md',
                      title: without_prefix('Meterpreter ')
                    },
                    {
                      path: 'Debugging-Dead-Meterpreter-Sessions.md'
                    },
                    {
                      path: 'Meterpreter-HTTP-Communication.md',
                      title: without_prefix('Meterpreter ')
                    },
                    {
                      path: 'Meterpreter-Stageless-Mode.md',
                      title: without_prefix('Meterpreter ')
                    },
                    {
                      path: 'How-to-get-started-with-writing-a-Meterpreter-script.md'
                    },
                    {
                      path: 'Powershell-Extension.md'
                    },
                    {
                      path: 'Python-Extension.md'
                    },
                  ]
                },
              ]
            },
            {
              title: 'Other',
              folder: 'other',
              children: [
                {
                  title: 'Oracle Support',
                  folder: 'oracle-support',
                  children: [
                    {
                      path: 'Oracle-Usage.md'
                    },
                    {
                      path: 'How-to-get-Oracle-Support-working-with-Kali-Linux.md'
                    },
                  ]
                },
                {
                  path: 'Information-About-Unmet-Browser-Exploit-Requirements.md'
                },
                {
                  path: 'Why-CVE-is-not-available.md'
                },
                {
                  path: 'How-to-use-the-Favorite-command.md'
                },
              ]
            },
          ]
        },
        {
          title: 'Development',
          folder: 'development',
          nav_order: 4,
          children: [
            {
              title: 'Get Started ',
              folder: 'get-started',
              nav_order: 1,
              children: [
                {
                  path: 'Contributing-to-Metasploit.md',
                  nav_order: 1
                },
                {
                  path: 'dev/Setting-Up-a-Metasploit-Development-Environment.md',
                  nav_order: 2
                },
                {
                  path: 'Sanitizing-PCAPs.md',
                  nav_order: 3
                },
                {
                  path: "Navigating-and-Understanding-Metasploit's-Codebase.md",
                  new_base_name: 'Navigating-and-Understanding-Metasploits-Codebase.md',
                  title: 'Navigating the codebase'
                },
                {
                  title: 'Git',
                  folder: 'git',
                  children: [
                    {
                      path: 'Keeping-in-sync-with-rapid7-master.md'
                    },
                    {
                      path: 'git/Git-cheatsheet.md'
                    },
                    {
                      path: 'git/Using-Git.md'
                    },
                    {
                      path: 'git/Git-Reference-Sites.md'
                    },
                    {
                      path: 'Remote-Branch-Pruning.md'
                    },
                  ]
                },
              ]
            },
            {
              title: 'Developing Modules',
              folder: 'developing-modules',
              nav_order: 2,
              children: [
                {
                  title: 'Guides',
                  folder: 'guides',
                  nav_order: 2,
                  children: [
                    {
                      path: 'How-to-get-started-with-writing-a-post-module.md',
                      title: 'Writing a post module'
                    },
                    {
                      path: 'Get-Started-Writing-an-Exploit.md',
                      title: 'Writing an exploit'
                    },
                    {
                      path: 'How-to-write-a-browser-exploit-using-HttpServer.md',
                      title: 'Writing a browser exploit'
                    },
                    {
                      title: 'Scanners',
                      folder: 'scanners',
                      nav_order: 2,
                      children: [
                        {
                          path: 'How-to-write-a-HTTP-LoginScanner-Module.md',
                          title: 'Writing a HTTP LoginScanner'
                        },
                        {
                          path: 'Creating-Metasploit-Framework-LoginScanners.md',
                          title: 'Writing an FTP LoginScanner'
                        },
                      ]
                    },
                    {
                      path: 'How-to-get-started-with-writing-an-auxiliary-module.md',
                      title: 'Writing an auxiliary module'
                    },
                    {
                      path: 'How-to-use-command-stagers.md'
                    },
                    {
                      path: 'How-to-write-a-check()-method.md',
                      new_base_name: 'How-to-write-a-check-method.md'
                    },
                    {
                      path: 'How-to-check-Microsoft-patch-levels-for-your-exploit.md'
                    },
                  ]
                },
                {
                  title: 'Libraries',
                  folder: 'libraries',
                  children: [
                    {
                      path: 'API.md',
                      nav_order: 0
                    },
                    {
                      title: 'Compiling C',
                      folder: 'c',
                      children: [
                        {
                          path: 'How-to-use-Metasploit-Framework-Compiler-Windows-to-compile-C-code.md',
                          title: 'Overview',
                          nav_order: 1
                        },
                        {
                          path: 'How-to-XOR-with-Metasploit-Framework-Compiler.md',
                          title: 'XOR Support'
                        },
                        {
                          path: 'How-to-decode-Base64-with-Metasploit-Framework-Compiler.md',
                          title: 'Base64 Support'
                        },
                        {
                          path: 'How-to-decrypt-RC4-with-Metasploit-Framework-Compiler.md',
                          title: 'RC4 Support'
                        },
                      ]
                    },
                    {
                      path: 'How-to-log-in-Metasploit.md',
                      title: 'Logging'
                    },
                    {
                      path: 'How-to-use-Railgun-for-Windows-post-exploitation.md',
                      title: 'Railgun'
                    },
                    {
                      path: 'How-to-zip-files-with-Msf-Util-EXE.to_zip.md',
                      new_base_name: 'How-to-zip-files-with-Msf-Util-EXE-to_zip.md',
                      title: 'Zip'
                    },
                    {
                      path: 'Handling-Module-Failures-with-`fail_with`.md',
                      new_base_name: 'Handling-Module-Failures-with-fail_with.md',
                      title: 'Fail_with'
                    },
                    {
                      path: 'How-to-use-Msf-Auxiliary-AuthBrute-to-write-a-bruteforcer.md',
                      title: 'AuthBrute'
                    },
                    {
                      path: 'How-to-Use-the-FILEFORMAT-mixin-to-create-a-file-format-exploit.md',
                      title: 'Fileformat'
                    },
                    {
                      path: 'SQL-Injection-(SQLi)-Libraries.md',
                      new_base_name: 'SQL-Injection-Libraries.md',
                      title: 'SQL Injection'
                    },
                    {
                      path: 'How-to-use-Powershell-in-an-exploit.md',
                      title: 'Powershell'
                    },
                    {
                      path: 'How-to-use-the-Seh-mixin-to-exploit-an-exception-handler.md',
                      title: 'SEH Exploitation'
                    },
                    {
                      path: 'How-to-clean-up-files-using-FileDropper.md',
                      title: 'FileDropper'
                    },
                    {
                      path: 'How-to-use-PhpEXE-to-exploit-an-arbitrary-file-upload-bug.md',
                      title: 'PhpExe'
                    },
                    {
                      title: 'HTTP',
                      folder: 'http',
                      children: [
                        {
                          path: 'How-to-send-an-HTTP-request-using-Rex-Proto-Http-Client.md'
                        },
                        {
                          path: 'How-to-parse-an-HTTP-response.md'
                        },
                        {
                          path: 'How-to-write-a-module-using-HttpServer-and-HttpClient.md'
                        },
                        {
                          path: 'How-to-Send-an-HTTP-Request-Using-HttpClient.md'
                        },
                        {
                          path: 'How-to-write-a-browser-exploit-using-BrowserExploitServer.md',
                          title: 'BrowserExploitServer'
                        },
                      ]
                    },
                    {
                      title: 'Deserialization',
                      folder: 'deserialization',
                      children: [
                        {
                          path: 'Dot-Net-Deserialization.md'
                        },
                        {
                          path: 'Generating-`ysoserial`-Java-serialized-objects.md',
                          new_base_name: 'Generating-ysoserial-Java-serialized-objects.md',
                          title: 'Java Deserialization'
                        }
                      ]
                    },
                    {
                      title: 'Obfuscation',
                      folder: 'obfuscation',
                      children: [
                        {
                          path: 'How-to-obfuscate-JavaScript-in-Metasploit.md',
                          title: 'JavaScript Obfuscation'
                        },
                        {
                          path: 'How-to-use-Metasploit-Framework-Obfuscation-CRandomizer.md',
                          title: 'C Obfuscation'
                        },
                      ]
                    },
                    {
                      path: 'How-to-use-the-Msf-Exploit-Remote-Tcp-mixin.md',
                      title: 'TCP'
                    },
                    {
                      path: 'How-to-do-reporting-or-store-data-in-module-development.md',
                      title: 'Reporting and Storing Data'
                    },
                    {
                      path: 'How-to-use-WbemExec-for-a-write-privilege-attack-on-Windows.md',
                      title: 'WbemExec'
                    },
                    {
                      title: 'SMB',
                      folder: 'smb',
                      children: [
                        {
                          path: 'What-my-Rex-Proto-SMB-Error-means.md'
                        },

                        {
                          path: 'Guidelines-for-Writing-Modules-with-SMB.md'
                        },
                      ]
                    },
                    {
                      path: 'Using-ReflectiveDLL-Injection.md',
                      title: 'ReflectiveDLL Injection'
                    },
                  ]
                },
                {
                  title: 'External Modules',
                  folder: 'external-modules',
                  nav_order: 3,
                  children: [
                    {
                      path: 'Writing-External-Metasploit-Modules.md',
                      title: 'Overview',
                      nav_order: 1
                    },
                    {
                      path: 'Writing-External-Python-Modules.md',
                      title: 'Writing Python Modules'
                    },
                    {
                      path: 'Writing-External-GoLang-Modules.md',
                      title: 'Writing GoLang Modules'
                    },
                  ]
                },
                {
                  title: 'Module metadata',
                  folder: 'module-metadata',
                  nav_order: 3,
                  children: [
                    {
                      path: 'How-to-use-datastore-options.md'
                    },
                    {
                      path: 'Module-Reference-Identifiers.md'
                    },
                    {
                      path: 'Definition-of-Module-Reliability,-Side-Effects,-and-Stability.md',
                      new_base_name: 'Definition-of-Module-Reliability-Side-Effects-and-Stability.md'
                    },
                  ]
                }
              ]
            },
            {
              title: 'Maintainers',
              folder: 'maintainers',
              children: [
                {
                  title: 'Process',
                  folder: 'process',
                  children: [
                    {
                      path: 'Guidelines-for-Accepting-Modules-and-Enhancements.md'
                    },
                    {
                      path: 'How-to-deprecate-a-Metasploit-module.md'
                    },
                    {
                      path: 'Landing-Pull-Requests.md'
                    },
                    {
                      path: 'Assigning-Labels.md'
                    },
                    {
                      path: 'Adding-Release-Notes-to-PRs.md',
                      title: 'Release Notes'
                    },
                    {
                      path: 'Rolling-back-merges.md'
                    },
                    {
                      path: 'Unstable-Modules.md'
                    },
                  ]
                },
                {
                  path: 'Committer-Rights.md'
                },
                {
                  title: 'Ruby Gems',
                  folder: 'ruby-gems',
                  children: [
                    {
                      path: 'How-to-add-and-update-gems-in-metasploit-framework.md',
                      title: 'Adding and Updating'
                    },
                    {
                      path: 'Testing-Rex-and-other-Gem-File-Updates-With-Gemfile.local-and-Gemfile.local.example.md',
                      new_base_name: 'using-local-gems.md',
                      title: 'Using local Gems'
                    },
                    {
                      path: 'Merging-Metasploit-Payload-Gem-Updates.md'
                    },
                  ]
                },
                {
                  path: 'Committer-Keys.md'
                },
                {
                  path: 'Metasploit-Loginpalooza.md'
                },
                {
                  path: 'Metasploit-Hackathons.md'
                },
                {
                  path: 'Downloads-by-Version.md'
                }
              ]
            },
            {
              title: 'Quality',
              folder: 'quality',
              children: [
                {
                  path: 'Style-Tips.md'
                },
                {
                  path: 'Msftidy.md'
                },
                {
                  path: 'Using-Rubocop.md'
                },
                {
                  path: 'Common-Metasploit-Module-Coding-Mistakes.md'
                },
                {
                  path: 'Writing-Module-Documentation.md'
                },
              ]
            },
            {
              title: 'Google Summer of Code',
              folder: 'google-summer-of-code',
              children: [
                {
                  path: 'GSoC-2020-Project-Ideas.md',
                  title: without_prefix('GSoC')
                },
                {
                  path: 'How-to-Apply-to-GSoC.md'
                },
                {
                  path: 'GSoC-2017-Student-Proposal.md',
                  title: without_prefix('GSoC')
                },
                {
                  path: 'GSoC-2021-Project-Ideas.md',
                  title: without_prefix('GSoC')
                },
                {
                  path: 'GSoC-2017-Project-Ideas.md',
                  title: without_prefix('GSoC')
                },
                {
                  path: 'GSoC-2018-Project-Ideas.md',
                  title: without_prefix('GSoC')
                },
                {
                  path: 'GSoC-2017-Mentor-Organization-Application.md',
                  title: without_prefix('GSoC')
                },
                {
                  path: 'GSoC-2019-Project-Ideas.md',
                  title: without_prefix('GSoC')
                },
              ]
            },
            {
              title: 'Proposals',
              folder: 'propsals',
              children: [
                {
                  path: 'Bundled-Modules-Proposal.md'
                },
                {
                  path: 'MSF6-Feature-Proposals.md'
                },
                {
                  path: 'RFC---Metasploit-URL-support.md',
                  new_base_name: 'Metasploit-URL-support-proposal.md'
                },
                {
                  path: 'Uberhandler.md'
                },
                {
                  path: 'Work-needed-to-allow-msfdb-to-use-postgresql-common.md'
                },
                {
                  path: 'Payload-Rename-Justification.md'
                },
              ]
            },
            {
              title: 'Roadmap',
              folder: 'roadmap',
              children: [
                {
                  path: 'Metasploit-Framework-Wish-List.md'
                },
                {
                  path: 'Metasploit-5.0-Release-Notes.md',
                  new_base_name: 'Metasploit-5-Release-Notes.md',
                  title: 'Metasploit Framework 5.0 Release Notes'
                },
                {
                  path: '2017-Roadmap-Review.md'
                },
                {
                  path: 'Metasploit-6.0-Development-Notes.md',
                  new_base_name: 'Metasploit-6-Release-Notes.md',
                  title: 'Metasploit Framework 6.0 Release Notes'
                },
                {
                  path: '2017-Roadmap.md'
                },
                {
                  path: 'Metasploit-Breaking-Changes.md'
                },
                {
                  path: 'Metasploit-Data-Service-Enhancements-(Goliath).md',
                  new_base_name: 'Metasploit-Data-Service-Enhancements-Goliath.md',
                  title: 'Metasploit Data Service'
                },
              ]
            },
          ]
        },
        {
          path: 'Contact.md',
          nav_order: 5
        },
      ]
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
      invalid_new_paths = new_paths.select { |path| File.basename(path) !~ /^[a-zA-Z0-9_-]*\.md$/ }
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
        '@red0xff',
        '@mkienow-r7',
        '@pbarry-r7',
        '@schierlm',
        '@timwr',
        '@zerosteiner',
        '@harmj0y'
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

  # Converts Wiki markdown pages into a valid Jekyll format
  class WikiMigration
    def run(config)
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
          content = preamble.rstrip + "\n"
        else
          content = File.read(File.join(WIKI_PATH, page[:path]))
          content = preamble + content
          content = link_corrector.rerender(content)
        end
        File.write(new_path, content, mode: 'w')
      end

      # Now that the docs folder is created, time to move the home.md file out
      FileUtils.mv('docs/home.md', 'index.md')
    end

    protected

    def link_corrector_for(config)
      link_corrector = LinkCorrector.new(config)
      config.each do |page|
        unless page[:folder]
          content = File.read(File.join(WIKI_PATH, page[:path]))
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
      server.mount_proc('/') do |_req, res|
        res.set_redirect(WEBrick::HTTPStatus::TemporaryRedirect, '/metasploit-framework/')
      end
      server.mount('/metasploit-framework', WEBrick::HTTPServlet::FileHandler, PRODUCTION_BUILD_ARTIFACTS)
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
    result = ""
    ::Open3.popen2e(
      { 'BUNDLE_GEMFILE' => File.join(Dir.pwd, 'Gemfile') },
      '/bin/bash', '--login', '-c', command
    ) do |stdin, stdout_and_stderr, wait_thread|
      stdin.close_write

      while wait_thread.alive?
        ready = IO.select([stdout_and_stderr], nil, nil, 1)

        if ready
          reads, _writes, _errors = ready

          reads.to_a.each do |io|
            data = io.read_nonblock(1024)
            puts data
            result += data
          rescue EOFError, Errno::EAGAIN
            # noop
          end
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
      config = Config.new
      migrator = WikiMigration.new
      migrator.run(config)
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
