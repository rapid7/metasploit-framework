# -*- coding: binary -*-

require 'rex/socket'
require 'rex/text'
require 'digest'

module Rex
module Proto
module Http

class HttpLoggerSubscriber < HttpSubscriber
  def initialize(logger:)
    raise RuntimeError, "Incompatible logger" unless logger.respond_to?(:print_line) && logger.respond_to?(:datastore)
    @logger = logger
  end

  # (see Rex::Proto::Http::HttpSubscriber#on_request)
  def on_request(request)
    if @logger.datastore['HttpTrace']
      http_trace_colors = @logger.datastore['HttpTraceColors'].blank? ? 'red/blu' : @logger.datastore['HttpTraceColors'] # Set the default colors if none were provided.
      http_trace_colors += '/' if http_trace_colors.count('/') == 0 # Append "/"" to the end of the string if no "/" were found in the string to ensure consistent formatting.
      request_color, response_color = http_trace_colors.gsub('/', ' / ').split('/').map { |color| color&.strip.blank? ? '' : "%bld%#{color.strip}" }
      request = request.to_s(headers_only: @logger.datastore['HttpTraceHeadersOnly'])
      @logger.print_line("#"*20)
      @logger.print_line("# Request:")
      @logger.print_line("#"*20)
      @logger.print_line("%clr#{request_color}#{request}%clr")
    end
  end

  # (see Rex::Proto::HttpSubscriber#on_response)
  def on_response(response)
    if @logger.datastore['HttpTrace']
      http_trace_colors = @logger.datastore['HttpTraceColors'].blank? ? 'red/blu' : @logger.datastore['HttpTraceColors'] # Set the default colors if none were provided.
      http_trace_colors += '/' if http_trace_colors.count('/') == 0 # Append "/"" to the end of the string if no "/" were found in the string to ensure consistent formatting.
      request_color, response_color = http_trace_colors.gsub('/', ' / ').split('/').map { |color| color&.strip.blank? ? '' : "%bld%#{color.strip}" }
      @logger.print_line("#"*20)
      @logger.print_line("# Response:")
      @logger.print_line("#"*20)
      if response
        response = response.to_terminal_output(headers_only: @logger.datastore['HttpTraceHeadersOnly'])
        @logger.print_line("%clr#{response_color}#{response}%clr")
      else
        @logger.print_line("No response received")
      end
    end
  end
end
end
end
end
