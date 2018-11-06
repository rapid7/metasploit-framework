# frozen_string_literal: true
require 'tmpdir'
require 'fileutils'
require 'open-uri'

module YARD
  module CLI
    # CLI command to return the objects that were added/removed from 2 versions
    # of a project (library, gem, working copy).
    # @since 0.6.0
    class Diff < Command
      def initialize
        super
        @list_all = false
        @use_git = false
        @compact = false
        @modified = true
        @verifier = Verifier.new
        @old_git_commit = nil
        @old_path = Dir.pwd
        log.show_backtraces = true
      end

      def description
        'Returns the object diff of two gems or .yardoc files'
      end

      def run(*args)
        registry = optparse(*args).map do |gemfile|
          if @use_git
            load_git_commit(gemfile)
            all_objects
          elsif load_gem_data(gemfile)
            log.info "Found #{gemfile}"
            all_objects
          else
            log.error "Cannot find gem #{gemfile}"
            nil
          end
        end.compact

        return if registry.size != 2

        first_object = nil
        [["Added objects", "A", added_objects(*registry)],
            ["Modified objects", "M", modified_objects(*registry)],
            ["Removed objects", "D", removed_objects(*registry)]].each do |name, short, objects|
          next if short == "M" && @modified == false
          next if objects.empty?
          last_object = nil
          all_objects_notice = false
          log.puts name + ":" unless @compact
          objects.sort_by(&:path).each do |object|
            if !@list_all && last_object && object.parent == last_object
              log.print " (...)" unless all_objects_notice
              all_objects_notice = true
              next
            elsif @compact
              log.puts if first_object
            else
              log.puts
            end
            all_objects_notice = false
            log.print "" + (@compact ? "#{short} " : "  ") +
                      object.path + " (#{object.file}:#{object.line})"
            last_object = object
            first_object = true
          end
          unless @compact
            log.puts; log.puts
          end
        end
        log.puts if @compact
      end

      private

      def all_objects
        return Registry.all if @verifier.expressions.empty?
        @verifier.run(Registry.all)
      end

      def added_objects(registry1, registry2)
        registry2.reject {|o| registry1.find {|o2| o2.path == o.path } }
      end

      def modified_objects(registry1, registry2)
        registry1.select do |obj|
          case obj
          when CodeObjects::MethodObject
            registry2.find {|o| obj == o && o.source != obj.source }
          when CodeObjects::ConstantObject
            registry2.find {|o| obj == o && o.value != obj.value }
          end
        end.compact
      end

      def removed_objects(registry1, registry2)
        registry1.reject {|o| registry2.find {|o2| o2.path == o.path } }
      end

      def load_git_commit(commit)
        Registry.clear
        commit_path = 'git_commit' + commit.gsub(/\W/, '_')
        tmpdir = File.join(Dir.tmpdir, commit_path)
        log.info "Expanding #{commit} to #{tmpdir}..."
        Dir.chdir(@old_path)
        FileUtils.mkdir_p(tmpdir)
        FileUtils.cp_r('.', tmpdir)
        Dir.chdir(tmpdir)
        log.info("git says: " + `git reset --hard #{commit}`.chomp)
        generate_yardoc(tmpdir)
      ensure
        Dir.chdir(@old_path)
        cleanup(commit_path)
      end

      def load_gem_data(gemfile)
        require_rubygems
        Registry.clear

        # First check for argument as .yardoc file
        [File.join(gemfile, '.yardoc'), gemfile].each do |yardoc|
          log.info "Searching for .yardoc db at #{yardoc}"
          next unless File.directory?(yardoc)
          Registry.load_yardoc(yardoc)
          Registry.load_all
          return true
        end

        # Next check installed RubyGems
        gemfile_without_ext = gemfile.sub(/\.gem$/, '')
        log.info "Searching for installed gem #{gemfile_without_ext}"
        YARD::GemIndex.each.find do |spec|
          next unless spec.full_name == gemfile_without_ext
          yardoc = Registry.yardoc_file_for_gem(spec.name, "= #{spec.version}")
          if yardoc
            Registry.load_yardoc(yardoc)
            Registry.load_all
          else
            log.enter_level(Logger::ERROR) do
              olddir = Dir.pwd
              Gems.run(spec.name, spec.version.to_s)
              Dir.chdir(olddir)
            end
          end
          return true
        end

        # Look for local .gem file
        gemfile += '.gem' unless gemfile =~ /\.gem$/
        log.info "Searching for local gem file #{gemfile}"
        if File.exist?(gemfile)
          File.open(gemfile, 'rb') do |io|
            expand_and_parse(gemfile, io)
          end
          return true
        end

        # Remote gemfile from rubygems.org
        url = "http://rubygems.org/downloads/#{gemfile}"
        log.info "Searching for remote gem file #{url}"
        begin
          open(url) {|io| expand_and_parse(gemfile, io) }
          return true
        rescue OpenURI::HTTPError
          nil # noop
        end
        false
      end

      def expand_and_parse(gemfile, io)
        dir = expand_gem(gemfile, io)
        generate_yardoc(dir)
        cleanup(gemfile)
      end

      def generate_yardoc(dir)
        Dir.chdir(dir) do
          log.enter_level(Logger::ERROR) { Yardoc.run('-n', '--no-save') }
        end
      end

      def expand_gem(gemfile, io)
        tmpdir = File.join(Dir.tmpdir, gemfile)
        FileUtils.mkdir_p(tmpdir)
        log.info "Expanding #{gemfile} to #{tmpdir}..."

        if Gem::VERSION >= '2.0.0'
          require 'rubygems/package/tar_reader'
          reader = Gem::Package::TarReader.new(io)
          reader.each do |pkg|
            next unless pkg.full_name == 'data.tar.gz'
            Zlib::GzipReader.wrap(pkg) do |gzio|
              tar = Gem::Package::TarReader.new(gzio)
              tar.each do |entry|
                file = File.join(tmpdir, entry.full_name)
                FileUtils.mkdir_p(File.dirname(file))
                File.open(file, 'wb') do |out|
                  out.write(entry.read)
                  begin
                    out.fsync
                  rescue NotImplementedError
                    nil # noop
                  end
                end
              end
            end
            break
          end
        else
          Gem::Package.open(io) do |pkg|
            pkg.each do |entry|
              pkg.extract_entry(tmpdir, entry)
            end
          end
        end

        tmpdir
      end

      def require_rubygems
        require 'rubygems'
        require 'rubygems/package'
      rescue LoadError => e
        log.error "Missing RubyGems, cannot run this command."
        raise(e)
      end

      def cleanup(gemfile)
        dir = File.join(Dir.tmpdir, gemfile)
        log.info "Cleaning up #{dir}..."
        FileUtils.rm_rf(dir)
      end

      def optparse(*args)
        opts = OptionParser.new
        opts.banner = "Usage: yard diff [options] oldgem newgem"
        opts.separator ""
        opts.separator "Example: yard diff yard-0.5.6 yard-0.5.8"
        opts.separator ""
        opts.separator "If the files don't exist locally, they will be grabbed using the `gem fetch`"
        opts.separator "command. If the gem is a .yardoc directory, it will be used. Finally, if the"
        opts.separator "gem name matches an installed gem (full name-version syntax), that gem will be used."

        opts.on('-a', '--all', 'List all objects, even if they are inside added/removed module/class') do
          @list_all = true
        end
        opts.on('--compact', 'Show compact results') { @compact = true }
        opts.on('--git', 'Compare versions from two git commit/branches') do
          @use_git = true
        end
        opts.on('--query QUERY', 'Only diff filtered objects') do |query|
          @verifier.add_expressions(query)
        end
        opts.on('--no-modified', 'Ignore modified objects') do
          @modified = false
        end
        common_options(opts)
        parse_options(opts, args)
        unless args.size == 2
          log.puts opts.banner
          exit(0)
        end

        args
      end
    end
  end
end
