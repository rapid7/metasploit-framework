# frozen_string_literal: true
require "pathname"

module YARD
  module CLI
    # CLI command to support internationalization (a.k.a. i18n).
    # I18n feature is based on gettext technology.
    # This command generates .pot file from docstring and extra
    # documentation.
    #
    # @since 0.8.0
    # @todo Support msgminit and msgmerge features?
    class I18n < Yardoc
      def initialize
        super
        @options.serializer.basepath = "po/yard.pot"
      end

      def description
        'Generates .pot file from source code and extra documentation'
      end

      def run(*args)
        if args.empty? || !args.first.nil?
          # fail early if arguments are not valid
          return unless parse_arguments(*args)
        end

        YARD.parse(files, excluded)

        serializer = options.serializer
        pot_file_path = Pathname.new(serializer.basepath).expand_path
        pot_file_dir_path, pot_file_basename = pot_file_path.split
        relative_base_path = Pathname.pwd.relative_path_from(pot_file_dir_path)
        serializer.basepath = pot_file_dir_path.to_s
        serializer.serialize(pot_file_basename.to_s,
                             generate_pot(relative_base_path.to_s))

        true
      end

      private

      def general_options(opts)
        opts.banner = "Usage: yard i18n [options] [source_files [- extra_files]]"
        opts.top.list.clear
        opts.separator "(if a list of source files is omitted, "
        opts.separator "  {lib,app}/**/*.rb ext/**/*.c is used.)"
        opts.separator ""
        opts.separator "Example: yard i18n -o yard.pot - FAQ LICENSE"
        opts.separator "  The above example outputs .pot file for files in"
        opts.separator "  lib/**/*.rb to yard.pot including the extra files"
        opts.separator "  FAQ and LICENSE."
        opts.separator ""
        opts.separator "A base set of options can be specified by adding a .yardopts"
        opts.separator "file to your base path containing all extra options separated"
        opts.separator "by whitespace."
        super(opts)
      end

      def generate_pot(relative_base_path)
        generator = YARD::I18n::PotGenerator.new(relative_base_path)
        objects = run_verifier(all_objects)
        generator.parse_objects(objects)
        generator.parse_files(options.files || [])
        generator.generate
      end
    end
  end
end
