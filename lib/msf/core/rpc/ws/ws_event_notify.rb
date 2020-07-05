module Msf
  module WS
    class EventNotify
      class Subscriber
        include Framework::Offspring
        def initialize(framework)
          self.framework = framework
        end

        def respond_to?(_name, *_args)
          # Why yes, I can do that.
          true
        end

        def on_session_open(session)
          res = {
            'type' => session.type.to_s,
            'tunnel_to_s' => session.tunnel_to_s,
            'via_exploit' => session.via_exploit.to_s,
            'via_payload' => session.via_payload.to_s
          }
          if (session.type.to_s == 'meterpreter')
            res['platform'] = session.platform.to_s
          end
          data = framework.websocket.wrap_websocket_data(:notify, __method__, res)
          framework.websocket.notify(:notify, data)
        end

        def on_session_close(session, reason = '')
          res = {
            'type' => session.type.to_s,
            'reason' => reason.to_s,
            'tunnel_to_s' => session.tunnel_to_s,
            'via_exploit' => session.via_exploit.to_s,
            'via_payload' => session.via_payload.to_s
          }
          if (session.type.to_s == 'meterpreter')
            res['platform'] = session.platform.to_s
          end
          data = framework.websocket.wrap_websocket_data(:notify, __method__, res)
          framework.websocket.notify(:notify, data)
        end

        def method_missing(_method_name, *_args)
        end

      end
      def initialize(framework, _opts)
        @subscriber = Subscriber.new(framework)
        subscribers = framework.events.instance_variable_get(:@session_event_subscribers).collect(&:class)
        if !subscribers.include?(@subscriber.class)
          framework.events.add_session_subscriber(@subscriber)
        end
      end
    end
  end
end
