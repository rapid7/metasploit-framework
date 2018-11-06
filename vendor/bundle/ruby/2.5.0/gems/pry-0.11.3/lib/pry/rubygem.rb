require 'rubygems'

class Pry
  module Rubygem

    class << self
      def installed?(name)
        if Gem::Specification.respond_to?(:find_all_by_name)
          Gem::Specification.find_all_by_name(name).any?
        else
          Gem.source_index.find_name(name).first
        end
      end

      # Get the gem spec object for the given gem name.
      #
      # @param [String] name
      # @return [Gem::Specification]
      def spec(name)
        specs = if Gem::Specification.respond_to?(:each)
                  Gem::Specification.find_all_by_name(name)
                else
                  Gem.source_index.find_name(name)
                end

        first_spec = specs.sort_by{ |spec| Gem::Version.new(spec.version) }.last

        first_spec or raise CommandError, "Gem `#{name}` not found"
      end

      # List gems matching a pattern.
      #
      # @param [Regexp] pattern
      # @return [Array<Gem::Specification>]
      def list(pattern = /.*/)
        if Gem::Specification.respond_to?(:each)
          Gem::Specification.select{|spec| spec.name =~ pattern }
        else
          Gem.source_index.gems.values.select{|spec| spec.name =~ pattern }
        end
      end

      # Completion function for gem-cd and gem-open.
      #
      # @param [String] so_far what the user's typed so far
      # @return [Array<String>] completions
      def complete(so_far)
        if so_far =~ / ([^ ]*)\z/
          self.list(%r{\A#{$2}}).map(&:name)
        else
          self.list.map(&:name)
        end
      end

      # Installs a gem with all its dependencies.
      #
      # @param [String] name
      # @return [void]
      def install(name)
        require 'rubygems/dependency_installer'
        gem_config = Gem.configuration['gem']
        gemrc_opts = (gem_config.nil? ? "" : gem_config.split(' '))
        destination = if gemrc_opts.include?('--user-install')
                        Gem.user_dir
                      elsif File.writable?(Gem.dir)
                        Gem.dir
                      else
                        Gem.user_dir
                      end
        installer = Gem::DependencyInstaller.new(:install_dir => destination)
        installer.install(name)
      rescue Errno::EACCES
        raise CommandError,
          "Insufficient permissions to install #{ Pry::Helpers::Text.green(name) }."
      rescue Gem::GemNotFoundException
        raise CommandError,
          "Gem #{ Pry::Helpers::Text.green(name) } not found. Aborting installation."
      else
        Gem.refresh
      end
    end

  end
end
