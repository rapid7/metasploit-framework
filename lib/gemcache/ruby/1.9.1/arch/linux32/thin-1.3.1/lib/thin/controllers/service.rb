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
          log ">> Thin service already installed at #{INITD_PATH}"
        else
          log ">> Installing thin service at #{INITD_PATH} ..."
          sh "mkdir -p #{File.dirname(INITD_PATH)}"
          log "writing #{INITD_PATH}"        
          File.open(INITD_PATH, 'w') do |f|
            f << ERB.new(File.read(TEMPLATE)).result(binding)
          end
          sh "chmod +x #{INITD_PATH}" # Make executable
        end
      
        sh "mkdir -p #{config_files_path}"

        log ''
        log "To configure thin to start at system boot:"
        log "on RedHat like systems:"
        log "  sudo /sbin/chkconfig --level 345 #{NAME} on"
        log "on Debian-like systems (Ubuntu):"
        log "  sudo /usr/sbin/update-rc.d -f #{NAME} defaults"
        log "on Gentoo:"
        log "  sudo rc-update add #{NAME} default"
        log ''
        log "Then put your config files in #{config_files_path}"
      end
    
      private
        def run(command)
          Dir[config_path + '/*'].each do |config|
            log "[#{command}] #{config} ..."
            Command.run(command, :config => config, :daemonize => true)
          end
        end
      
        def sh(cmd)
          log cmd
          system(cmd)
        end
    end
  end
end