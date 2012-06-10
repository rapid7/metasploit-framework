module Rack
  # A multipart form data parser, adapted from IOWA.
  #
  # Usually, Rack::Request#POST takes care of calling this.
  module Multipart
    autoload :UploadedFile, 'rack/multipart/uploaded_file'
    autoload :Parser, 'rack/multipart/parser'
    autoload :Generator, 'rack/multipart/generator'

    EOL = "\r\n"
    MULTIPART_BOUNDARY = "AaB03x"
    MULTIPART = %r|\Amultipart/.*boundary=\"?([^\";,]+)\"?|n
    TOKEN = /[^\s()<>,;:\\"\/\[\]?=]+/
    CONDISP = /Content-Disposition:\s*#{TOKEN}\s*/i
    DISPPARM = /;\s*(#{TOKEN})=("(?:\\"|[^"])*"|#{TOKEN})*/
    RFC2183 = /^#{CONDISP}(#{DISPPARM})+$/i
    BROKEN_QUOTED = /^#{CONDISP}.*;\sfilename="(.*?)"(?:\s*$|\s*;\s*#{TOKEN}=)/i
    BROKEN_UNQUOTED = /^#{CONDISP}.*;\sfilename=(#{TOKEN})/i
    MULTIPART_CONTENT_TYPE = /Content-Type: (.*)#{EOL}/ni
    MULTIPART_CONTENT_DISPOSITION = /Content-Disposition:.*\s+name="?([^\";]*)"?/ni
    MULTIPART_CONTENT_ID = /Content-ID:\s*([^#{EOL}]*)/ni

    class << self
      def parse_multipart(env)
        Parser.new(env).parse
      end

      def build_multipart(params, first = true)
        Generator.new(params, first).dump
      end
    end

  end
end