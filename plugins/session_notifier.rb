module Msf
  class Plugin::SessionNotifier < Msf::Plugin

    include Msf::SessionEvent

    class Exception < ::RuntimeError ; end

    class SessionNotifierCommandDispatcher

      include Msf::Ui::Console::CommandDispatcher

      attr_reader :sms_client
      attr_reader :sms_carrier
      attr_reader :sms_number
      attr_reader :smtp_address
      attr_reader :smtp_port
      attr_reader :smtp_username
      attr_reader :smtp_password
      attr_reader :smtp_from
      attr_reader :minimum_ip
      attr_reader :maximum_ip

      def name
        'SessionNotifier'
      end

      def commands
        {
          'set_session_smtp_address'       => 'Set the SMTP address for the session notifier',
          'set_session_smtp_port'          => 'Set the SMTP port for the session notifier',
          'set_session_smtp_username'      => 'Set the SMTP username',
          'set_session_smtp_password'      => 'Set the SMTP password',
          'set_session_smtp_from'          => 'Set the from field of SMTP',
          'set_session_mobile_number'      => 'Set the 10-digit mobile number you want to notify',
          'set_session_mobile_carrier'     => 'Set the mobile carrier of the phone',
          'set_session_minimum_ip'         => 'Set the minimum session IP range you want to be notified for',
          'set_session_maximum_ip'         => 'Set the maximum session IP range you want to be notified for',
          'save_session_notifier_settings' => 'Save all the session notifier settings to framework',
          'start_session_notifier'         => 'Start notifying sessions',
          'stop_session_notifier'          => 'Stop notifying sessions',
          'restart_session_notifier'       => 'Restart notifying sessions'
        }
      end

      def initialize(driver)
        super(driver)
        load_settings_from_config
      end

      def cmd_set_session_smtp_address(*args)
        @smtp_address = args[0]
      end

      def cmd_set_session_smtp_port(*args)
        port = args[0]
        if port =~ /^\d+$/
          @smtp_port = args[0]
        else
          print_error('Invalid port setting. Must be a number.')
        end
      end

      def cmd_set_session_smtp_username(*args)
        @smtp_username = args[0]
      end

      def cmd_set_session_smtp_password(*args)
        @smtp_password = args[0]
      end

      def cmd_set_session_smtp_from(*args)
        @smtp_from = args[0]
      end

      def cmd_set_session_mobile_number(*args)
        num = args[0]
        if num =~ /^\d{10}$/
          @sms_number = args[0]
        else
          print_error('Invalid phone format. It should be a 10-digit number that looks like: XXXXXXXXXX')
        end
      end

      def cmd_set_session_mobile_carrier(*args)
        @sms_carrier = args[0].to_sym
      end

      def cmd_set_session_minimum_ip(*args)
        ip = args[0]
        if ip.blank?
          @minimum_ip = nil
        elsif Rex::Socket.dotted_ip?(ip)
          @minimum_ip = IPAddr.new(ip)
        else
          print_error('Invalid IP format')
        end
      end

      def cmd_set_session_maximum_ip(*args)
        ip = args[0]
        if ip.blank?
          @maximum_ip = nil
        elsif Rex::Socket.self.dotted_ip?(ip)
          @maximum_ip = IPAddr.new(ip)
        else
          print_error('Invalid IP format')
        end
      end

      def cmd_save_session_notifier_settings(*args)
        save_settings_to_config
        print_status("Session Notifier settings saved in config file.")
      end

      def cmd_start_session_notifier(*args)
        if is_session_notifier_subscribed?
          print_status('You already have an active session notifier.')
          return
        end

        begin
          validate_settings!
          self.framework.events.add_session_subscriber(self)
          smtp = Rex::Proto::Sms::Model::Smtp.new(
            address: self.smtp_address,
            port: self.smtp_port,
            username: self.smtp_username,
            password: self.smtp_password,
            login_type: :login,
            from: self.smtp_from
          )
          @sms_client = Rex::Proto::Sms::Client.new(carrier: self.sms_carrier, smtp_server: smtp)
          print_status("Session notification started.")
        rescue Msf::Plugin::SessionNotifier::Exception, Rex::Proto::Sms::Exception => e
          print_error(e.message)
        end
      end

      def cmd_stop_session_notifier(*args)
        self.framework.events.remove_session_subscriber(self)
        print_status("Session notification stopped.")
      end

      def cmd_restart_session_notifier(*args)
        cmd_stop_session_notifier(args)
        cmd_start_session_notifier(args)
      end

      def on_session_open(session)
        subject = "You have a new #{session.type} session!"
        msg = "#{session.tunnel_peer} (#{session.session_host}) #{session.info ? "\"#{session.info.to_s}\"" : nil}"
        notify_session(session, subject, msg)
      end

      private

      def save_settings_to_config
        config_file = Msf::Config.config_file
        ini = Rex::Parser::Ini.new(config_file)
        ini.add_group(name) unless ini[name]
        ini[name]['smtp_address']  = self.smtp_address
        ini[name]['smtp_port']     = self.smtp_port
        ini[name]['smtp_username'] = self.smtp_username
        ini[name]['smtp_password'] = self.smtp_password
        ini[name]['smtp_from']     = self.smtp_from
        ini[name]['sms_number']    = self.sms_number
        ini[name]['sms_carrier']   = self.sms_carrier
        ini[name]['minimum_ip']    = self.minimum_ip.to_s unless self.minimum_ip.blank?
        ini[name]['maximum_ip']    = self.maximum_ip.to_s unless self.maximum_ip.blank?
        ini.to_file(config_file)
      end

      def load_settings_from_config
        config_file = Msf::Config.config_file
        ini = Rex::Parser::Ini.new(config_file)
        group = ini[name]
        if group
          @sms_carrier   = group['sms_carrier'].to_sym     if group['sms_carrier']
          @sms_number    = group['sms_number']             if group['sms_number']
          @smtp_address  = group['smtp_address']           if group['smtp_address']
          @smtp_port     = group['smtp_port']              if group['smtp_port']
          @smtp_username = group['smtp_username']          if group['smtp_username']
          @smtp_password = group['smtp_password']          if group['smtp_password']
          @smtp_from     = group['smtp_from']              if group['smtp_from']
          @minimum_ip    = IPAddr.new(group['minimum_ip']) if group['minimum_ip']
          @maximum_ip    = IPAddr.new(group['maximum_ip']) if group['maximum_ip']

          print_status('Session Notifier settings loaded from config file.')
        end
      end

      def is_session_notifier_subscribed?
        subscribers = framework.events.instance_variable_get(:@session_event_subscribers).collect { |s| s.class }
        subscribers.include?(self.class)
      end

      def notify_session(session, subject, msg)
        if is_in_range?(session)
          @sms_client.send_text_to_phones([self.sms_number], subject, msg)
          print_status("Session notified to: #{self.sms_number}")
        end
      end

      def is_in_range?(session)
        # If both blank, it means we're not setting a range.
        return true if self.minimum_ip.blank? && self.maximum_ip.blank?

        ip = IPAddr.new(session.session_host)

        if self.minimum_ip && !self.maximum_ip
          # There is only a minimum IP
          self.minimum_ip < ip
        elsif !self.minimum_ip && self.maximum_ip
          # There is only a max IP
          self.maximum_ip > ip
        else
          # Both ends are set
          range = self.minimum_ip..self.maximum_ip
          range.include?(ip)
        end
      end

      def validate_settings!
        if self.smtp_address.nil? || self.smtp_port.nil? ||
          self.smtp_username.nil? || self.smtp_password.nil? ||
          self.smtp_from.nil?
          raise Msf::Plugin::SessionNotifier::Exception, "All Session Notifier's settings must be configured."
        end
      end

    end

    def name
      'SessionNotifier'
    end

    def initialize(framework, opts)
      super
      add_console_dispatcher(SessionNotifierCommandDispatcher)
    end

    def cleanup
      remove_console_dispatcher(name)
    end

    def name
      'SessionNotifier'
    end

    def desc
      'This plugin notifies you a new session via SMS.'
    end

  end
end
