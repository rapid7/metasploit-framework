require 'net/https'
require 'net/http'
require 'uri'
module Msf
  class Plugin::DingtalkNotifier < Msf::Plugin

    include Msf::SessionEvent

    class Exception < ::RuntimeError; end

    class DingtalkNotifierCommandDispatcher

      include Msf::Ui::Console::CommandDispatcher
      attr_reader :dingtalk_webhook
      attr_reader :minimum_ip_webhook
      attr_reader :maximum_ip_webhook

      def name
        'DingtalkNotifier'
      end

      def commands
        {
          'set_dingtalk_minimum_ip'         => 'Set the minimum session IP range you want to be notified for',
          'set_dingtalk_maximum_ip'         => 'Set the maximum session IP range you want to be notified for',
          'set_dingtalk_webhook'            => 'Set the DingTalk webhook for the session notifier (keyword: session).',
          'save_dingtalk_notifier_settings' => 'Save all the session notifier settings to framework',
          'start_dingtalk_notifier'         => 'Start notifying dingtalk',
          'stop_dingtalk_notifier'          => 'Stop notifying dingtalk',
          'restart_dingtalk_notifier'       => 'Restart notifying dingtalk'
        }
      end

      def initialize(driver)
        super(driver)
        load_settings_from_config
      end

      def cmd_set_dingtalk_minimum_ip(*args)
        ip = args[0]
        if ip.blank?
          @minimum_ip_webhook = nil
        elsif Rex::Socket.dotted_ip?(ip)
          @minimum_ip_webhook = IPAddr.new(ip)
        else
          print_error('Invalid IP format')
        end
      end

      def cmd_set_dingtalk_maximum_ip(*args)
        ip = args[0]
        if ip.blank?
          @maximum_ip_webhook = nil
        elsif Rex::Socket.self.dotted_ip?(ip)
          @maximum_ip_webhook = IPAddr.new(ip)
        else
          print_error('Invalid IP format')
        end
      end

      def cmd_set_dingtalk_webhook(*args)
        webhook_url = args[0]
        if webhook_url.blank?
          @dingtalk_webhook = nil
        elsif !(webhook_url =~ URI::DEFAULT_PARSER.make_regexp).nil?
          @dingtalk_webhook = webhook_url
        else
          print_error('Invalid webhook_url')
        end
      end

      def cmd_save_dingtalk_notifier_settings(*_args)
        save_settings_to_config
        print_status('Dingtalk Notifier settings saved in config file.')
      end

      def cmd_start_dingtalk_notifier(*_args)
        if session_notifier_subscribed?
          print_status('You already have an active dingtalk notifier.')
          return
        end

        begin
          framework.events.add_session_subscriber(self)
          if !dingtalk_webhook.nil?
            print_status('DingTalk notification started.')
          end
        rescue Msf::Plugin::DingtalkNotifier::Exception => e
          print_error(e.message)
        end
      end

      def cmd_stop_dingtalk_notifier(*_args)
        framework.events.remove_session_subscriber(self)
        print_status('DingTalk notification stopped.')
      end

      def cmd_restart_dingtalk_notifier(*args)
        cmd_stop_dingtalk_notifier(args)
        cmd_start_dingtalk_notifier(args)
      end

      def on_session_open(session)
        notify_session(session)
      end

      private

      def save_settings_to_config
        config_file = Msf::Config.config_file
        ini = Rex::Parser::Ini.new(config_file)
        ini.add_group(name) unless ini[name]
        ini[name]['dingtalk_webhook'] = dingtalk_webhook.to_s unless dingtalk_webhook.blank?
        ini.to_file(config_file)
      end

      def load_settings_from_config
        config_file = Msf::Config.config_file
        ini = Rex::Parser::Ini.new(config_file)
        group = ini[name]
        if group
          @dingtalk_webhook = group['dingtalk_webhook'] if group['dingtalk_webhook']
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
        body = JSON.parse(res.body)
        print_status((body['errcode'] == 0) ? 'Session notified to DingTalk.' : 'Failed to send notification.')
      end

      def notify_session(session)
        if in_range?(session) && !dingtalk_webhook.nil?
          send_text_to_dingtalk(session)
        end
      end

      def in_range?(session)
        # If both blank, it means we're not setting a range.
        return true if minimum_ip_webhook.blank? && maximum_ip_webhook.blank?

        ip = IPAddr.new(session.session_host)

        if minimum_ip_webhook && !maximum_ip_webhook
          # There is only a minimum IP
          minimum_ip_webhook < ip
        elsif !minimum_ip_webhook && maximum_ip_webhook
          # There is only a max IP
          maximum_ip_webhook > ip
        else
          # Both ends are set
          range = minimum_ip_webhook..maximum_ip_webhook
          range.include?(ip)
        end
      end

    end

    def name
      'DingtalkNotifier'
    end

    def initialize(framework, opts)
      super
      add_console_dispatcher(DingtalkNotifierCommandDispatcher)
    end

    def cleanup
      remove_console_dispatcher(name)
    end

    def desc
      'This plugin notifies you a new session via webhook.'
    end

  end
end
