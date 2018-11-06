require 'net/ssh/loggable'
module Net 
  module SSH 
    module Connection

      class Keepalive
        include Loggable
      
        def initialize(session)
          @last_keepalive_sent_at = nil
          @unresponded_keepalive_count = 0
          @session = session
          self.logger = session.logger
        end
      
        def options
          @session.options
        end
      
        def enabled?
          options[:keepalive]
        end
      
        def interval
          options[:keepalive_interval] || Session::DEFAULT_IO_SELECT_TIMEOUT
        end
      
        def should_send?
          return false unless enabled?
          return true unless @last_keepalive_sent_at
          Time.now - @last_keepalive_sent_at >= interval
        end
      
        def keepalive_maxcount
          (options[:keepalive_maxcount] || 3).to_i
        end
      
        def send_as_needed(was_events)
          return if was_events
          return unless should_send?
          info { "sending keepalive #{@unresponded_keepalive_count}" }
      
          @unresponded_keepalive_count += 1
          @session.send_global_request("keepalive@openssh.com") { |success, response|
            debug { "keepalive response successful. Missed #{@unresponded_keepalive_count - 1} keepalives" }
            @unresponded_keepalive_count = 0
          }
          @last_keepalive_sent_at = Time.now
          if keepalive_maxcount > 0 && @unresponded_keepalive_count > keepalive_maxcount
            error { "Timeout, server #{@session.host} not responding. Missed #{@unresponded_keepalive_count - 1} timeouts." }
            @unresponded_keepalive_count = 0
            raise Net::SSH::Timeout, "Timeout, server #{@session.host} not responding."
          end
        end
      end

    end
  end
end
