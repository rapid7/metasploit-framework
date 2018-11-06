# frozen_string_literal: true
module YARD
  module CLI
    # CLI command to view or edit configuration options
    # @since 0.6.2
    class Config < Command
      # @return [Symbol, nil] the key to view/edit, if any
      attr_accessor :key

      # @return [Array, nil] the list of values to set (or single value), if modifying
      attr_accessor :values

      # @return [Boolean] whether to reset the {#key}
      attr_accessor :reset

      # @return [Boolean] whether the value being set should be inside a list
      attr_accessor :as_list

      # @return [Boolean] whether to append values to existing key
      attr_accessor :append

      # @return [String, nil] command to use when configuring ~/.gemrc file.
      #   If the string is nil, configuration should not occur.
      attr_accessor :gem_install_cmd

      def initialize
        super
        self.key = nil
        self.values = []
        self.reset = false
        self.append = false
        self.as_list = false
        self.gem_install_cmd = nil
      end

      def description
        'Views or edits current global configuration'
      end

      def run(*args)
        optparse(*args)
        if gem_install_cmd
          configure_gemrc
        elsif key
          if reset || !values.empty?
            modify_item
          else
            view_item
          end
        else
          list_configuration
        end
      end

      private

      def configure_gemrc
        return unless gem_install_cmd

        require 'rubygems'

        ['install', :install, 'gem', :gem].find do |cmd|
          conf = Gem.configuration[cmd] || ""
          next if conf.empty? && cmd != :gem

          conf = conf.split(/\s+/)
          conf.delete_if {|c| c =~ /^--(no-)?document\b/ } # scrub doc args
          conf |= ["--document=#{gem_install_cmd}"]
          conf = conf.join(' ')

          Gem.configuration[cmd] = conf
          Gem.configuration.write
          log.puts "Updated #{Gem.configuration.path || '~/.gemrc'}: '#{cmd}: #{conf}'"
          true
        end
      end

      def modify_item
        if reset
          log.debug "Resetting #{key}"
          YARD::Config.options[key] = YARD::Config::DEFAULT_CONFIG_OPTIONS[key]
        else
          log.debug "Setting #{key} to #{values.inspect}"
          items = encode_values
          current_items = YARD::Config.options[key]
          items = [current_items].flatten + [items].flatten if append
          YARD::Config.options[key] = items
        end
        YARD::Config.save
      end

      def view_item
        log.debug "Viewing #{key}"
        log.puts YARD::Config.options[key].inspect
      end

      def list_configuration
        log.debug "Listing configuration"
        require 'yaml'
        log.puts YAML.dump(YARD::Config.options).sub(/\A--.*\n/, '').gsub(/\n\n/, "\n")
      end

      def encode_values
        if values.size == 1 && !as_list
          encode_value(values.first)
        else
          values.map {|v| encode_value(v) }
        end
      end

      def encode_value(value)
        case value
        when /^-?\d+/; value.to_i
        when "true"; true
        when "false"; false
        else value
        end
      end

      def optparse(*args)
        list = false
        self.as_list = false
        self.append = false
        opts = OptionParser.new
        opts.banner = "Usage: yard config [options] [item [value ...]]"
        opts.separator ""
        opts.separator "Example: yard config load_plugins true"
        opts.separator ""
        opts.separator "Views and sets configuration items. If an item is provided"
        opts.separator "With no value, the item is viewed. If a value is provided,"
        opts.separator "the item is modified. Specifying no item is equivalent to --list."
        opts.separator "If you specify multiple space delimited values, these are"
        opts.separator "parsed as an array of values."
        opts.separator ""
        opts.separator "Note that `true` and `false` are reserved words."
        opts.separator ""
        opts.separator "---------------------------------------------------------"
        opts.separator ""
        opts.separator "Configuring RubyGems support:"
        opts.separator ""
        opts.separator "YARD can automatically generate the YRI index or HTML"
        opts.separator "documentation in a `gem install` by adding the following"
        opts.separator "to your ~/.gemrc file:"
        opts.separator ""
        opts.separator "    gem: \"--document=yri\""
        opts.separator ""
        opts.separator "Note: you can add 'yard' to also generate HTML docs."
        opts.separator "  You can also add 'ri' to continue generating RDoc."
        opts.separator ""
        opts.separator "You can also run the following command to configure this"
        opts.separator "behavior automatically:"
        opts.separator ""
        opts.separator "    $ yard config --gem-install-yri"
        opts.separator ""
        opts.separator "Add --gem-install-yard to also generate HTML."
        opts.separator ""
        opts.separator "---------------------------------------------------------"
        opts.separator ""
        opts.separator "General options:"

        opts.on('-l', '--list', 'List current configuration') do
          list = true
        end
        opts.on('-r', '--reset', 'Resets the specific item to default') do
          self.reset = true
        end

        opts.separator ""
        opts.separator "Modifying keys:"

        opts.on('-a', '--append', 'Appends items to existing key values') do
          self.append = true
        end
        opts.on('--as-list', 'Forces the value(s) to be wrapped in an array') do
          self.as_list = true
        end

        opts.separator ""
        opts.separator "Add RubyGems install hook:"

        opts.on('--gem-install-yri', 'Configures ~/.gemrc to run yri on a gem install') do
          self.gem_install_cmd = 'yri' if gem_install_cmd != 'yard'
        end

        opts.on('--gem-install-yard', 'Configures ~/.gemrc to run yard on a gem install') do
          self.gem_install_cmd = 'yard'
        end

        common_options(opts)
        parse_options(opts, args)
        args = [] if list
        self.key = args.shift.to_sym if args.size >= 1
        self.values = args if args.size >= 1
        args
      end
    end
  end
end
