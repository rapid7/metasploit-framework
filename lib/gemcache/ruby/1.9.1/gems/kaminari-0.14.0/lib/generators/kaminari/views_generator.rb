module Kaminari
  module Generators
    SHOW_API = 'http://github.com/api/v2/json/blob/show/amatsuda/kaminari_themes'
    ALL_API  = 'http://github.com/api/v2/json/blob/all/amatsuda/kaminari_themes/master'

    class ViewsGenerator < Rails::Generators::NamedBase
      source_root File.expand_path('../../../../app/views/kaminari', __FILE__)

      class_option :template_engine, :type => :string, :aliases => '-e', :desc => 'Template engine for the views. Available options are "erb", "haml", and "slim".'

      def self.banner #:nodoc:
        <<-BANNER.chomp
rails g kaminari:views THEME [options]

    Copies all paginator partial templates to your application.
    You can choose a template THEME by specifying one from the list below:

        - default
            The default one.
            This one is used internally while you don't override the partials.
#{themes.map {|t| "        - #{t.name}\n#{t.description}"}.join("\n")}
BANNER
      end

      desc ''
      def copy_or_fetch #:nodoc:
        return copy_default_views if file_name == 'default'

        themes = self.class.themes
        if theme = themes.detect {|t| t.name == file_name}
          download_templates theme
        else
          say %Q[no such theme: #{file_name}\n  avaliable themes: #{themes.map(&:name).join ", "}]
        end
      end

      private
      def self.themes
        begin
          @themes ||= open ALL_API do |json|
#             @themes ||= open(File.join(File.dirname(__FILE__), '../../../spec/generators/sample.json')) do |json|
            files = ActiveSupport::JSON.decode(json)['blobs']
            hash = files.group_by {|fn, _| fn[0...(fn.index('/') || 0)]}.delete_if {|fn, _| fn.blank?}
            hash.map do |name, files|
              Theme.new name, files
            end
          end
        rescue SocketError
          []
        end
      end

      def download_templates(theme)
        theme.templates_for(template_engine).each do |template|
          say "      downloading #{template.name} from kaminari_themes..."
          get "#{SHOW_API}/#{template.sha}", template.name
        end
      end

      def copy_default_views
        filename_pattern = File.join self.class.source_root, "*.html.#{template_engine}"
        Dir.glob(filename_pattern).map {|f| File.basename f}.each do |f|
          copy_file f, "app/views/kaminari/#{f}"
        end
      end

      def template_engine
        options[:template_engine].try(:to_s).try(:downcase) || 'erb'
      end
    end

    Template = Struct.new(:name, :sha) do
      def description?
        name == 'DESCRIPTION'
      end

      def view?
        name =~ /^app\/views\//
      end

      def engine #:nodoc:
        File.extname(name).sub /^\./, ''
      end
    end

    class Theme
      attr_accessor :name
      def initialize(name, templates) #:nodoc:
        @name, @templates = name, templates.map {|fn, sha| Template.new fn.sub(/^#{name}\//, ''), sha}
      end

      def description #:nodoc:
        file = @templates.detect(&:description?)
        return "#{' ' * 12}#{name}" unless file
        open("#{SHOW_API}/#{file.sha}").read.chomp.gsub /^/, ' ' * 12
      end

      def templates_for(template_engine) #:nodoc:
        @templates.select {|t| !t.description?}.select {|t| !t.view? || (t.engine == template_engine)}
      end
    end
  end
end
