#
# $Id$
# $Revision$
#

module Msf

class Plugin::EventTester < Msf::Plugin
  class Subscriber
    def respond_to?(name)
      # Why yes, I can do that.
      true
    end
    def method_missing(name, *args)
      $stdout.puts("Event fired: #{name}(#{args.join(", ")})")
    end
  end

  def name; "event_tester"; end

  def initialize(framework, opts)
    super
    @subscriber = Subscriber.new
    framework.events.add_exploit_subscriber(@subscriber)
    framework.events.add_session_subscriber(@subscriber)
    framework.events.add_general_subscriber(@subscriber)
    framework.events.add_db_subscriber(@subscriber)
    framework.events.add_ui_subscriber(@subscriber)
  end
  def cleanup
    framework.events.remove_exploit_subscriber(@subscriber)
    framework.events.remove_session_subscriber(@subscriber)
    framework.events.remove_general_subscriber(@subscriber)
    framework.events.remove_db_subscriber(@subscriber)
    framework.events.remove_ui_subscriber(@subscriber)
  end
end

end
