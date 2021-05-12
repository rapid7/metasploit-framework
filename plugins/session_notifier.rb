require 'net/https'
require 'net/http'
require 'uri'
module Msf
  class Plugin::SessionNotifier < Msf::Plugin

    include Msf::SessionEvent

    class Exception < ::RuntimeError; end

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
      attr_reader :dingtalk_webhook
      attr_reader :gotify_address
      attr_reader :gotify_sslcert_path

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
          'set_session_dingtalk_webhook'   => 'Set the DingTalk webhook for the session notifier (keyword: session).',
          'set_session_gotify_address'     => 'Set the Gotify address for the session notifier',
          'set_session_gotify_sslcert_path' => 'Set the path to load your Gotify SSL cert (if you want to use HTTPS)',
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

      def cmd_set_session_gotify_address(*args)
        webhook_url = args[0]
        if webhook_url.blank?
          @gotify_address = nil
        elsif !(webhook_url =~ URI::DEFAULT_PARSER.make_regexp).nil?
          @gotify_address = webhook_url
        else
          @gotify_address = nil
          print_error('Invalid gotify_address')
        end
      end

      def cmd_set_session_gotify_sslcert_path(*args)
        cert_path = args[0]
        if !cert_path.blank? && ::File.file?(cert_path) && ::File.readable?(cert_path)
          @gotify_sslcert_path = cert_path
          print_status("Set Gotify ssl_mode ON! Your cert path is #{gotify_sslcert_path}")
        else
          @gotify_sslcert_path = nil
          print_status('Set Gotify ssl_mode OFF!')
        end
      end

      def cmd_set_session_dingtalk_webhook(*args)
        webhook_url = args[0]
        if webhook_url.blank?
          @dingtalk_webhook = nil
        elsif !(webhook_url =~ URI::DEFAULT_PARSER.make_regexp).nil?
          @dingtalk_webhook = webhook_url
        else
          print_error('Invalid webhook_url')
        end
      end

      def cmd_save_session_notifier_settings(*_args)
        save_settings_to_config
        print_status('Session Notifier settings saved in config file.')
      end

      def cmd_start_session_notifier(*_args)
        if session_notifier_subscribed?
          print_status('You already have an active session notifier.')
          return
        end

        begin
          framework.events.add_session_subscriber(self)
          if validate_sms_settings?
            smtp = Rex::Proto::Sms::Model::Smtp.new(
              address: smtp_address,
              port: smtp_port,
              username: smtp_username,
              password: smtp_password,
              login_type: :login,
              from: smtp_from
            )
            @sms_client = Rex::Proto::Sms::Client.new(carrier: sms_carrier, smtp_server: smtp)
            print_status('Session notification started.')
          end
          if !dingtalk_webhook.nil?
            print_status('DingTalk notification started.')
          end
          if !gotify_address.nil?
            print_status('Gotify notification started.')
          end
        rescue Msf::Plugin::SessionNotifier::Exception, Rex::Proto::Sms::Exception => e
          print_error(e.message)
        end
      end

      def cmd_stop_session_notifier(*_args)
        framework.events.remove_session_subscriber(self)
        print_status('Session notification stopped.')
      end

      def cmd_restart_session_notifier(*args)
        cmd_stop_session_notifier(args)
        cmd_start_session_notifier(args)
      end

      def on_session_open(session)
        subject = "You have a new #{session.type} session!"
        msg = "#{session.tunnel_peer} (#{session.session_host}) #{session.info ? "\"#{session.info}\"" : nil}"
        notify_session(session, subject, msg)
      end

      private

      def save_settings_to_config
        config_file = Msf::Config.config_file
        ini = Rex::Parser::Ini.new(config_file)
        ini.add_group(name) unless ini[name]
        ini[name]['smtp_address']     = smtp_address
        ini[name]['smtp_port']        = smtp_port
        ini[name]['smtp_username']    = smtp_username
        ini[name]['smtp_password']    = smtp_password
        ini[name]['smtp_from']        = smtp_from
        ini[name]['sms_number']       = sms_number
        ini[name]['sms_carrier']      = sms_carrier
        ini[name]['minimum_ip']       = minimum_ip.to_s unless minimum_ip.blank?
        ini[name]['maximum_ip']       = maximum_ip.to_s unless maximum_ip.blank?
        ini[name]['dingtalk_webhook'] = dingtalk_webhook.to_s unless dingtalk_webhook.blank?
        ini[name]['gotify_address']   = gotify_address.to_s unless gotify_address.blank?
        ini[name]['gotify_sslcert_path']   = gotify_sslcert_path.to_s unless gotify_sslcert_path.blank?
        ini.to_file(config_file)
      end

      def load_settings_from_config
        config_file = Msf::Config.config_file
        ini = Rex::Parser::Ini.new(config_file)
        group = ini[name]
        if group
          @sms_carrier      = group['sms_carrier'].to_sym     if group['sms_carrier']
          @sms_number       = group['sms_number']             if group['sms_number']
          @smtp_address     = group['smtp_address']           if group['smtp_address']
          @smtp_port        = group['smtp_port']              if group['smtp_port']
          @smtp_username    = group['smtp_username']          if group['smtp_username']
          @smtp_password    = group['smtp_password']          if group['smtp_password']
          @smtp_from        = group['smtp_from']              if group['smtp_from']
          @minimum_ip       = IPAddr.new(group['minimum_ip']) if group['minimum_ip']
          @maximum_ip       = IPAddr.new(group['maximum_ip']) if group['maximum_ip']
          @dingtalk_webhook = group['dingtalk_webhook']       if group['dingtalk_webhook']
          @gotify_address   = group['gotify_address']         if group['gotify_address']
          @gotify_sslcert_path = group['gotify_sslcert_path'] if group['gotify_sslcert_path']
          print_status('Session Notifier settings loaded from config file.')
        end
      end

      def session_notifier_subscribed?
        subscribers = framework.events.instance_variable_get(:@session_event_subscribers).collect(&:class)
        subscribers.include?(self.class)
      end

      def send_text_to_dingtalk(session)
        # https://ding-doc.dingtalk.com/doc#/serverapi2/qf2nxq/9e91d73c
        uri_parser = URI.parse(dingtalk_webhook)
        markdown_text = "## You have a new #{session.type} session!\n\n" \
        "**platform** : #{session.platform}\n\n" \
        "**tunnel** : #{session.tunnel_to_s}\n\n" \
        "**arch** : #{session.arch}\n\n" \
        "**info** : > #{session.info ? session.info.to_s : nil}"
        json_post_data = JSON.pretty_generate({
          msgtype: 'markdown',
          markdown: { title: 'Session Notifier', text: markdown_text }
        })
        http = Net::HTTP.new(uri_parser.host, uri_parser.port)
        http.use_ssl = true
        request = Net::HTTP::Post.new(uri_parser.request_uri)
        request.content_type = 'application/json'
        request.body = json_post_data
        res = http.request(request)
        if res.nil? || res.body.blank?
          print_error("No response recieved from the DingTalk server!")
          return nil
        end
        begin
          body = JSON.parse(res.body)
          print_status((body['errcode'] == 0) ? 'Session notified to DingTalk.' : 'Failed to send notification.')
        rescue JSON::ParserError
          print_error("Couldn't parse the JSON returned from the DingTalk server!")
        end
      end

      def send_text_to_gotify(session)
        # https://gotify.net/docs/more-pushmsg
        uri_parser = URI.parse(gotify_address)
        message_text =
        "Platform : #{session.platform}\n" \
        "Tunnel : #{session.tunnel_to_s}\n" \
        "Arch : #{session.arch}\n" \
        "Info : > #{session.info ? session.info.to_s : nil}"
        json_post_data = JSON.pretty_generate({
          title: "A #{session.platform}/#{session.type} Session is On!",
          message: message_text,
          priority: 10
        })
        http = Net::HTTP.new(uri_parser.host, uri_parser.port)
        if !gotify_sslcert_path.nil? && ::File.file?(gotify_sslcert_path) && ::File.readable?(gotify_sslcert_path)
          http.use_ssl = true
          http.verify_mode = OpenSSL::SSL::VERIFY_PEER
          store = OpenSSL::X509::Store.new
          store.add_file(gotify_sslcert_path)
        end
        request = Net::HTTP::Post.new(uri_parser.request_uri)
        request.content_type = 'application/json'
        request.body = json_post_data
        res = http.request(request)
        if res.nil? || res.body.blank?
          print_error("No response recieved from the Gotify server!")
          return nil
        end
        begin
          body = JSON.parse(res.body)
          print_status((body['priority'] == 10) ? 'Session notified to Gotify.' : 'Failed to send notification.')
        rescue JSON::ParserError
          print_error("Couldn't parse the JSON returned from the Gotify server!")
        end
      end

      def notify_session(session, subject, msg)
        if in_range?(session) && validate_sms_settings?
          @sms_client.send_text_to_phones([sms_number], subject, msg)
          print_status("Session notified to: #{sms_number}")
        end
        if in_range?(session) && !dingtalk_webhook.nil?
          send_text_to_dingtalk(session)
        end
        if in_range?(session) && !gotify_address.nil?
          send_text_to_gotify(session)
        end
      end

      def in_range?(session)
        # If both blank, it means we're not setting a range.
        return true if minimum_ip.blank? && maximum_ip.blank?

        ip = IPAddr.new(session.session_host)

        if minimum_ip && !maximum_ip
          # There is only a minimum IP
          minimum_ip < ip
        elsif !minimum_ip && maximum_ip
          # There is only a max IP
          maximum_ip > ip
        else
          # Both ends are set
          range = minimum_ip..maximum_ip
          range.include?(ip)
        end
      end

      def validate_sms_settings?
        !(smtp_address.nil? || smtp_port.nil? ||
        smtp_username.nil? || smtp_password.nil? ||
        smtp_from.nil?)
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

    def desc
      'This plugin notifies you a new session via SMS.'
    end

  end
end
