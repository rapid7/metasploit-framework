# frozen_string_literal: true
module YARD
  module Server
    module Commands
      # Displays documentation for a specific object identified by the path
      class DisplayObjectCommand < LibraryCommand
        include DocServerHelper

        def run
          if path.empty?
            if options.readme
              filename = options.readme.filename
              opts = adapter.options.merge(
                :index => true, :library => library,
                :path => filename.sub(%r{^#{library.source_path.to_s}/}, '')
              )
              self.status, self.headers, self.body =
                *DisplayFileCommand.new(opts).call(request)
              cache(body)
              return
            else
              self.path = 'index'
            end
          end
          return index if path == 'index'

          object = Registry.at(object_path)
          if object
            options.update(:type => :layout)
            render(object)
          else
            not_found
          end
        end

        def index
          Registry.load_all

          options.update(
            :object => '_index.html',
            :objects => Registry.all(:module, :class),
            :type => :layout
          )
          render
        end

        def not_found
          super
          self.body = "Could not find object: #{object_path}"
        end

        private

        def object_path
          return @object_path if @object_path
          if path == "toplevel"
            @object_path = :root
          else
            @object_path = path.sub(':', '#').gsub('/', '::').sub(/^toplevel\b/, '').sub(/\.html$/, '')
          end
        end
      end
    end
  end
end
