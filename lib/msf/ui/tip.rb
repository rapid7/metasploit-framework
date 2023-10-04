# -*- coding: binary -*-
# frozen_string_literal: true

module Msf
  module Ui
    ###
    #
    # Module that contains some most excellent tips.
    #
    ###
    module Tip
      def self.highlight(string)
        "%grn#{string}%clr"
      end

      COMMON_TIPS = [
        "View all productivity tips with the #{highlight('tips')} command",
        "Enable verbose logging with #{highlight('set VERBOSE true')}",
        "When in a module, use #{highlight('back')} to go back to the top level prompt",
        "Tired of setting RHOSTS for modules? Try globally setting it with #{highlight('setg RHOSTS x.x.x.x')}",
        "Enable HTTP request and response logging with #{highlight('set HttpTrace true')}",
        "You can upgrade a shell to a Meterpreter session on many platforms using #{highlight('sessions -u <session_id>')}",
        "Open an interactive Ruby terminal with #{highlight('irb')}",
        "Use the #{highlight('resource')} command to run commands from a file",
        "To save all commands executed since start up to a file, use the #{highlight('makerc')} command",
        "View advanced module options with #{highlight('advanced')}",
        "You can use #{highlight('help')} to view all available commands",
        "Use #{highlight('help <command>')} to learn more about any command",
        "View a module's description using #{highlight('info')}, or the enhanced version in your browser with #{highlight('info -d')}",
        "After running #{highlight('db_nmap')}, be sure to check out the result of #{highlight('hosts')} and #{highlight('services')}",
        "Save the current environment with the #{highlight('save')} command, future console restarts will use this environment again",
        "Search can apply complex filters such as #{highlight('search cve:2009 type:exploit')}, see all the filters with #{highlight('help search')}",
        "Metasploit can be configured at startup, see #{highlight('msfconsole --help')} to learn more",
        "Display the Framework log using the #{highlight('log')} command, learn more with #{highlight('help log')}",
        "Network adapter names can be used for IP options #{highlight('set LHOST eth0')}",
        "Use #{highlight('sessions -1')} to interact with the last opened session",
        "View missing module options with #{highlight('show missing')}",
        "Start commands with a space to avoid saving them to history",
        "You can pivot connections over sessions started with the ssh_login modules",
        "Use the #{highlight('analyze')} command to suggest runnable modules for hosts",
        "Set the current module's RHOSTS with database values using #{highlight('hosts -R')} or #{highlight('services -R')}",
        "Use the 'capture' plugin to start multiple authentication-capturing and poisoning services",
        "The #{highlight('use')} command supports fuzzy searching to try and select the intended module, e.g. #{highlight('use kerberos/get_ticket')} or #{highlight('use kerberos forge silver ticket')}"
      ].freeze
      private_constant :COMMON_TIPS

      DEVELOPER_TIPS = [
        "Writing a custom module? After editing your module, why not try the #{highlight('reload')} command",
        "Use the #{highlight('edit')} command to open the currently active module in your editor",
      ].freeze
      private_constant :DEVELOPER_TIPS

      ALL_TIPS = COMMON_TIPS + DEVELOPER_TIPS
      private_constant :ALL_TIPS

      def self.all
        ALL_TIPS
      end

      def self.sample
        ALL_TIPS.sample
      end
    end
  end
end
