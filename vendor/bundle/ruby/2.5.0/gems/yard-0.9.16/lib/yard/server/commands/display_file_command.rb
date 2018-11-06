# frozen_string_literal: true
module YARD
  module Server
    module Commands
      # Displays a README or extra file.
      #
      # @todo Implement better support for detecting binary (image) filetypes
      class DisplayFileCommand < LibraryCommand
        attr_accessor :index

        def run
          filename = File.cleanpath(File.join(library.source_path, path))
          raise NotFoundError unless File.file?(filename)
          if filename =~ /\.(jpe?g|gif|png|bmp)$/i
            headers['Content-Type'] = StaticFileCommand::DefaultMimeTypes[$1.downcase] || 'text/html'
            render File.read_binary(filename)
          else
            file = CodeObjects::ExtraFileObject.new(filename)
            options.update :object => Registry.root,
                           :type => :layout,
                           :file => file,
                           :index => index ? true : false
            render
          end
        end
      end
    end
  end
end
