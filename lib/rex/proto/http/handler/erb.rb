# -*- coding: binary -*-
require 'erb'
include ERB::Util

module Rex
module Proto
module Http

###
#
# This class implements a handler for ERB (.rhtml) template files.  This is
# based off the webrick handler.
#
###
class Handler::Erb < Handler

  #
  # ERB handlers required a relative resource so that the full path name can
  # be computed.
  #
  def self.relative_resource_required?
    true
  end

  #
  # Initializes the ERB handler
  #
  def initialize(server, root_path, opts = {})
    super(server)

    self.root_path = root_path
    self.opts = opts

    self.opts['MimeType'] = "text/html" unless self.opts['MimeType']
  end

  #
  # Called when a request arrives.
  #
  def on_request(cli, req)
    resource = req.relative_resource

    # Make sure directory traversals aren't happening
    if (resource =~ /\.\./)
      wlog("Erb::on_request: Dangerous request performed: #{resource}",
        LogSource)
      return
    # If the request is for the root directory, use the document index file.
    elsif (resource == '/')
      resource << opts['DocumentIndex'] || 'index.rhtml'
    end

    begin
      resp = Response.new

      # Calculate the actual file path on disk.
      file_path = root_path + resource

      # Serialize the contents of the file
      data = ''

      File.open(file_path, 'rb') { |f|
        data = f.read
      }

      # Set the content-type to text/html by default.  We do this before
      # evaluation so that the script can change it.
      resp['Content-Type'] = server ? server.mime_type(resource) : 'text/html'

      # If the requested file is a ruby html file, evaluate it.
      if (File.extname(file_path) == ".rhtml")
        # Evaluate the data and set the output as the response body.
        resp.body = evaluate(ERB.new(data), cli, req, resp)
      # Otherwise, just set the body to the data that was read.
      else
        resp.body = data
      end
    rescue Errno::ENOENT
      server.send_e404(cli, req)
    rescue
      elog("Erb::on_request: #{$!}\n#{$@.join("\n")}", LogSource)

      resp.code    = 500
      resp.message = "Internal Server Error"
      resp.body =
        "<html><head>" +
        "<title>Internal Server Error</title>" +
        "</head><body> " +
        "<h1>Internal Server Error</h1>" +
        "The server encountered an error:<br/><br/> <b>" + html_escape($!) + "</b><br/><br/>" +
        "Stack trace:<br/><br/>" +
        $@.map { |e| html_escape(e.to_s) }.join("<br/>") +
        "</body></html>"
    end

    # Send the response to the
    if (cli and resp)
      cli.send_response(resp)
    end

    resp
  end

  #
  # Evaulates the ERB context in a specific binding context.
  #
  def evaluate(erb, cli, request, response)
    # If the thing that created this handler wanted us to use a callback
    # instead of the default behavior, then let's do that.
    if (opts['ErbCallback'])
      opts['ErbCallback'].call(erb, cli, request, response)
    else
      Module.new.module_eval {
        query_string = request.qstring
        meta_vars = request.meta_vars
        erb.result(binding)
      }
    end
  end

protected

  attr_accessor :root_path, :opts # :nodoc:

end

end
end
end
