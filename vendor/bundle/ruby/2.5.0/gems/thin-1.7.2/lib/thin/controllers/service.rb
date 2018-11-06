require 'erb'

module Thin
  module Controllers
    # System service controller to launch all servers which
    # config files are in a directory.
    class Service < Controller
      INITD_PATH          = File.directory?('/etc/rc.d') ? '/etc/rc.d/thin' : '/etc/init.d/thin'
      DEFAULT_CONFIG_PATH = '/etc/thin'
      TEMPLATE            = File.dirname(__FILE__) + '/service.sh.erb'
    
      def initialize(options)
        super
      
        raise PlatformNotSupported, 'Running as a service only supported on Linux' unless Thin.linux?
      end
    
      def config_path
        @options[:all] || DEFAULT_CONFIG_PATH
      end
    
      def start
        run :start
      end
    
      def stop
        run :stop
      end
    
      def restart
        run :restart
      end
    
      def install(config_files_path=DEFAULT_CONFIG_PATH)
        if File.exist?(INITD_PATH)
          log_info "Thin service already installed at #{INITD_PATH}"
        else
          log_info "Installing thin service at #{INITD_PATH} ..."
          sh "mkdir -p #{File.dirname(INITD_PATH)}"
          log_info "writing #{INITD_PATH}"        
          File.open(INITD_PATH, 'w') do |f|
            f << ERB.new(File.read(TEMPLATE)).result(binding)
          end
          sh "chmod +x #{INITD_PATH}" # Make executable
        end
      
        sh "mkdir -p #{config_files_path}"

        log_info ''
        log_info "To configure thin to start at system boot:"
        log_info "on RedHat like systems:"
        log_info "  sudo /sbin/chkconfig --level 345 #{NAME} on"
        log_info "on Debian-like systems (Ubuntu):"
        log_info "  sudo /usr/sbin/update-rc.d -f #{NAME} defaults"
        log_info "on Gentoo:"
        log_info "  sudo rc-update add #{NAME} default"
        log_info ''
        log_info "Then put your config files in #{config_files_path}"
      end
    
      private
        def run(command)
          Dir[config_path + '/*'].each do |config|
            next if config.end_with?("~")
            log_info "[#{command}] #{config} ..."
            Command.run(command, :config => config, :daemonize => true)
          end
        end
      
        def sh(cmd)
          log_info cmd
          system(cmd)
        end
    end
  end
end
