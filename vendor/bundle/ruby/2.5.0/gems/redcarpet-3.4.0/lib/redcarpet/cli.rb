require 'redcarpet'
require 'optparse'

module Redcarpet
  # This class aims at easing the creation of custom
  # binary for your needs. For example, you can add new
  # options or change the existing ones. The parsing
  # is handled by Ruby's OptionParser. For instance:
  #
  #   class Custom::CLI < Redcarpet::CLI
  #     def self.options_parser
  #       super.tap do |opts|
  #         opts.on("--rainbow") do
  #           @@options[:rainbow] = true
  #         end
  #       end
  #     end
  #
  #     def self.render_object
  #       @@options[:rainbow] ? RainbowRender : super
  #     end
  #   end
  class CLI
    def self.options_parser
      @@options = {
        render_extensions: {},
        parse_extensions: {},
        smarty_pants: false
      }

      OptionParser.new do |opts|
        opts.banner = "Usage: redcarpet [--parse <extension>...] " \
                      "[--render <extension>...] [--smarty] <file>..."

        opts.on("--parse EXTENSION", "Enable a parsing extension") do |ext|
          ext = ext.gsub('-', '_').to_sym
          @@options[:parse_extensions][ext] = true
        end

        opts.on("--render EXTENSION", "Enable a rendering extension") do |ext|
          ext = ext.gsub('-', '_').to_sym
          @@options[:render_extensions][ext] = true
        end

        opts.on("--smarty", "Enable Smarty Pants") do
          @@options[:smarty_pants] = true
        end

        opts.on_tail("-v", "--version", "Display the current version") do
          STDOUT.puts "Redcarpet #{Redcarpet::VERSION}"
          exit
        end

        opts.on_tail("-h", "--help", "Display this help message") do
          puts opts
          exit
        end
      end
    end

    def self.process(args)
      self.legacy_parse!(args)
      self.options_parser.parse!(args)
      STDOUT.write parser_object.render(ARGF.read)
    end

    def self.render_object
      @@options[:smarty_pants] ? Render::SmartyHTML : Render::HTML
    end

    def self.parser_object
      renderer = render_object.new(@@options[:render_extensions])
      Redcarpet::Markdown.new(renderer, @@options[:parse_extensions])
    end

    def self.legacy_parse!(args) # :nodoc:
      # Workaround for backward compatibility as OptionParser
      # doesn't support the --flag-OPTION syntax.
      args.select {|a| a =~ /--(parse|render)-/ }.each do |arg|
        args.delete(arg)
        arg = arg.partition(/\b-/)
        args.push(arg.first, arg.last)
      end
    end
  end
end
