require 'rubygems'
require 'rake'
require 'rake/tasklib'
require 'date'
require 'set'

module GithubGem

  # Detects the gemspc file of this project using heuristics.
  def self.detect_gemspec_file
    FileList['*.gemspec'].first
  end

  # Detects the main include file of this project using heuristics
  def self.detect_main_include
    if File.exist?(File.expand_path("../lib/#{File.basename(detect_gemspec_file, '.gemspec').gsub(/-/, '/')}.rb", detect_gemspec_file))
      "lib/#{File.basename(detect_gemspec_file, '.gemspec').gsub(/-/, '/')}.rb"
    elsif FileList['lib/*.rb'].length == 1
      FileList['lib/*.rb'].first
    else
      nil
    end
  end

  class RakeTasks

    include Rake::DSL if Rake.const_defined?('DSL')

    attr_reader   :gemspec, :modified_files
    attr_accessor :gemspec_file, :task_namespace, :main_include, :root_dir, :spec_pattern, :test_pattern, :remote, :remote_branch, :local_branch

    # Initializes the settings, yields itself for configuration
    # and defines the rake tasks based on the gemspec file.
    def initialize(task_namespace = :gem)
      @gemspec_file   = GithubGem.detect_gemspec_file
      @task_namespace = task_namespace
      @main_include   = GithubGem.detect_main_include
      @modified_files = Set.new
      @root_dir       = Dir.pwd
      @test_pattern   = 'test/**/*_test.rb'
      @spec_pattern   = 'spec/**/*_spec.rb'
      @local_branch   = 'master'
      @remote         = 'origin'
      @remote_branch  = 'master'

      yield(self) if block_given?

      load_gemspec!
      define_tasks!
    end

    protected

    def git
      @git ||= ENV['GIT'] || 'git'
    end

    # Define Unit test tasks
    def define_test_tasks!
      require 'rake/testtask'

      namespace(:test) do
        Rake::TestTask.new(:basic) do |t|
          t.pattern = test_pattern
          t.verbose = true
          t.libs << 'test'
        end
      end

      desc "Run all unit tests for #{gemspec.name}"
      task(:test => ['test:basic'])
    end

    # Defines RSpec tasks
    def define_rspec_tasks!
      require 'rspec/core/rake_task'

      namespace(:spec) do
        desc "Verify all RSpec examples for #{gemspec.name}"
        RSpec::Core::RakeTask.new(:basic) do |t|
          t.pattern = spec_pattern
        end

        desc "Verify all RSpec examples for #{gemspec.name} and output specdoc"
        RSpec::Core::RakeTask.new(:specdoc) do |t|
          t.pattern = spec_pattern
          t.rspec_opts = ['--format', 'documentation', '--color']
        end

        desc "Run RCov on specs for #{gemspec.name}"
        RSpec::Core::RakeTask.new(:rcov) do |t|
          t.pattern = spec_pattern
          t.rcov = true
          t.rcov_opts = ['--exclude', '"spec/*,gems/*"', '--rails']
        end
      end

      desc "Verify all RSpec examples for #{gemspec.name} and output specdoc"
      task(:spec => ['spec:specdoc'])
    end

    # Defines the rake tasks
    def define_tasks!

      define_test_tasks!  if has_tests?
      define_rspec_tasks! if has_specs?

      namespace(@task_namespace) do
        desc "Updates the filelist in the gemspec file"
        task(:manifest) { manifest_task }

        desc "Builds the .gem package"
        task(:build => :manifest) { build_task }

        desc "Sets the version of the gem in the gemspec"
        task(:set_version => [:check_version, :check_current_branch]) { version_task }
        task(:check_version => :fetch_origin) { check_version_task }

        task(:fetch_origin) { fetch_origin_task }
        task(:check_current_branch) { check_current_branch_task }
        task(:check_clean_status) { check_clean_status_task }
        task(:check_not_diverged => :fetch_origin) { check_not_diverged_task }

        checks = [:check_current_branch, :check_clean_status, :check_not_diverged, :check_version]
        checks.unshift('spec:basic') if has_specs?
        checks.unshift('test:basic') if has_tests?
        # checks.push << [:check_rubyforge] if gemspec.rubyforge_project

        desc "Perform all checks that would occur before a release"
        task(:release_checks => checks)

        release_tasks = [:release_checks, :set_version, :build, :github_release, :gemcutter_release]
        # release_tasks << [:rubyforge_release] if gemspec.rubyforge_project

        desc "Release a new version of the gem using the VERSION environment variable"
        task(:release => release_tasks) { release_task }
        
        namespace(:release) do
          desc "Release the next version of the gem, by incrementing the last version segment by 1"
          task(:next => [:next_version] + release_tasks) { release_task }

          desc "Release the next version of the gem, using a patch increment (0.0.1)"
          task(:patch => [:next_patch_version] + release_tasks) { release_task }

          desc "Release the next version of the gem, using a minor increment (0.1.0)"
          task(:minor => [:next_minor_version] + release_tasks) { release_task }

          desc "Release the next version of the gem, using a major increment (1.0.0)"
          task(:major => [:next_major_version] + release_tasks) { release_task }
        end

        # task(:check_rubyforge)   { check_rubyforge_task }
        # task(:rubyforge_release) { rubyforge_release_task }
        task(:gemcutter_release) { gemcutter_release_task }
        task(:github_release => [:commit_modified_files, :tag_version]) { github_release_task }
        task(:tag_version) { tag_version_task }
        task(:commit_modified_files) { commit_modified_files_task }

        task(:next_version)       { next_version_task }
        task(:next_patch_version)  { next_version_task(:patch) }
        task(:next_minor_version) { next_version_task(:minor) }
        task(:next_major_version) { next_version_task(:major) }
        
        desc "Updates the gem release tasks with the latest version on Github"
        task(:update_tasks) { update_tasks_task }
      end
    end

    # Updates the files list and test_files list in the gemspec file using the list of files
    # in the repository and the spec/test file pattern.
    def manifest_task
      # Load all the gem's files using "git ls-files"
      repository_files = `#{git} ls-files`.split("\n")
      test_files       = Dir[test_pattern] + Dir[spec_pattern]

      update_gemspec(:files, repository_files)
      update_gemspec(:test_files, repository_files & test_files)
    end

    # Builds the gem
    def build_task
      sh "gem build -q #{gemspec_file}"
      Dir.mkdir('pkg') unless File.exist?('pkg')
      sh "mv #{gemspec.name}-#{gemspec.version}.gem pkg/#{gemspec.name}-#{gemspec.version}.gem"
    end

    def newest_version
      `#{git} tag`.split("\n").map { |tag| tag.split('-').last }.compact.map { |v| Gem::Version.new(v) }.max || Gem::Version.new('0.0.0')
    end

    def next_version(increment = nil)
      next_version = newest_version.segments
      increment_index = case increment
        when :micro then 3
        when :patch then 2
        when :minor then 1
        when :major then 0
        else next_version.length - 1
      end
      
      next_version[increment_index] ||= 0
      next_version[increment_index] = next_version[increment_index].succ
      ((increment_index + 1)...next_version.length).each { |i| next_version[i] = 0 }
      
      Gem::Version.new(next_version.join('.'))
    end

    def next_version_task(increment = nil)
      ENV['VERSION'] = next_version(increment).version
      puts "Releasing version #{ENV['VERSION']}..."
    end

    # Updates the version number in the gemspec file, the VERSION constant in the main
    # include file and the contents of the VERSION file.
    def version_task
      update_gemspec(:version, ENV['VERSION']) if ENV['VERSION']
      update_gemspec(:date, Date.today)

      update_version_file(gemspec.version)
      update_version_constant(gemspec.version)
    end

    def check_version_task
      raise "#{ENV['VERSION']} is not a valid version number!" if ENV['VERSION'] && !Gem::Version.correct?(ENV['VERSION'])
      proposed_version = Gem::Version.new((ENV['VERSION'] || gemspec.version).dup)
      raise "This version (#{proposed_version}) is not higher than the highest tagged version (#{newest_version})" if newest_version >= proposed_version
    end

    # Checks whether the current branch is not diverged from the remote branch
    def check_not_diverged_task
      raise "The current branch is diverged from the remote branch!" if `#{git} rev-list HEAD..#{remote}/#{remote_branch}`.split("\n").any?
    end

    # Checks whether the repository status ic clean
    def check_clean_status_task
      raise "The current working copy contains modifications" if `#{git} ls-files -m`.split("\n").any?
    end

    # Checks whether the current branch is correct
    def check_current_branch_task
      raise "Currently not on #{local_branch} branch!" unless `#{git} branch`.split("\n").detect { |b| /^\* / =~ b } == "* #{local_branch}"
    end

    # Fetches the latest updates from Github
    def fetch_origin_task
      sh git, 'fetch', remote
    end

    # Commits every file that has been changed by the release task.
    def commit_modified_files_task
      really_modified = `#{git} ls-files -m #{modified_files.entries.join(' ')}`.split("\n")
      if really_modified.any?
        really_modified.each { |file| sh git, 'add', file }
        sh git, 'commit', '-m', "Released #{gemspec.name} gem version #{gemspec.version}."
      end
    end

    # Adds a tag for the released version
    def tag_version_task
      sh git, 'tag', '-a', "#{gemspec.name}-#{gemspec.version}", '-m', "Released #{gemspec.name} gem version #{gemspec.version}."
    end

    # Pushes the changes and tag to github
    def github_release_task
      sh git, 'push', '--tags', remote, remote_branch
    end

    def gemcutter_release_task
      sh "gem", 'push', "pkg/#{gemspec.name}-#{gemspec.version}.gem"
    end

    # Gem release task.
    # All work is done by the task's dependencies, so just display a release completed message.
    def release_task
      puts
      puts "Release successful."
    end

    private

    # Checks whether this project has any RSpec files
    def has_specs?
      FileList[spec_pattern].any?
    end

    # Checks whether this project has any unit test files
    def has_tests?
      FileList[test_pattern].any?
    end

    # Loads the gemspec file
    def load_gemspec!
      @gemspec = eval(File.read(@gemspec_file))
    end

    # Updates the VERSION file with the new version
    def update_version_file(version)
      if File.exists?('VERSION')
        File.open('VERSION', 'w') { |f| f << version.to_s }
        modified_files << 'VERSION'
      end
    end

    # Updates the VERSION constant in the main include file if it exists
    def update_version_constant(version)
      if main_include && File.exist?(main_include)
        file_contents = File.read(main_include)
        if file_contents.sub!(/^(\s+VERSION\s*=\s*)[^\s].*$/) { $1 + version.to_s.inspect }
          File.open(main_include, 'w') { |f| f << file_contents }
          modified_files << main_include
        end
      end
    end

    # Updates an attribute of the gemspec file.
    # This function will open the file, and search/replace the attribute using a regular expression.
    def update_gemspec(attribute, new_value, literal = false)

      unless literal
        new_value = case new_value
          when Array        then "%w(#{new_value.join(' ')})"
          when Hash, String then new_value.inspect
          when Date         then new_value.strftime('%Y-%m-%d').inspect
          else              raise "Cannot write value #{new_value.inspect} to gemspec file!"
        end
      end

      spec   = File.read(gemspec_file)
      regexp = Regexp.new('^(\s+\w+\.' + Regexp.quote(attribute.to_s) + '\s*=\s*)[^\s].*$')
      if spec.sub!(regexp) { $1 + new_value }
        File.open(gemspec_file, 'w') { |f| f << spec }
        modified_files << gemspec_file

        # Reload the gemspec so the changes are incorporated
        load_gemspec!
        
        # Also mark the Gemfile.lock file as changed because of the new version.
        modified_files << 'Gemfile.lock' if File.exist?(File.join(root_dir, 'Gemfile.lock'))
      end
    end

    # Updates the tasks file using the latest file found on Github
    def update_tasks_task
      require 'net/https'
      require 'uri'
      
      uri = URI.parse('https://raw.github.com/wvanbergen/github-gem/master/tasks/github-gem.rake')
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      response = http.request(Net::HTTP::Get.new(uri.path))

      if Net::HTTPSuccess === response
        open(__FILE__, "w") { |file| file.write(response.body) }
        relative_file = File.expand_path(__FILE__).sub(%r[^#{@root_dir}/], '')
        if `#{git} ls-files -m #{relative_file}`.split("\n").any?
          sh git, 'add', relative_file
          sh git, 'commit', '-m', "Updated to latest gem release management tasks."
        else
          puts "Release managament tasks already are at the latest version."
        end
      else
        raise "Download failed with HTTP status #{response.code}!"
      end
    end
  end
end
