require 'rbconfig'

module FSSM::Support
  class << self
    def usable_backend
      case
        when mac? && rb_fsevent?
          'RBFSEvent'
        when linux? && rb_inotify?
          'Inotify'
        else
          'Polling'
      end
    end
    
    def optimal_backend_dependency
      return case
        when mac?     then  ['rb-fsevent', '>= 0.4.3.1']
        when linux?   then  ['rb-inotify', '>= 0.8.8']
        else                [nil, nil]
      end
    end

    def backend
      @@backend ||= usable_backend
    end

    def jruby?
      defined?(JRUBY_VERSION)
    end

    def mac?
      RbConfig::CONFIG['target_os'] =~ /darwin/i
    end

    def lion?
      RbConfig::CONFIG['target_os'] =~ /darwin11/i
    end

    def linux?
      RbConfig::CONFIG['target_os'] =~ /linux/i
    end

    def rb_fsevent?
      begin
        require 'rb-fsevent'
        defined?(FSEvent::VERSION) ? FSEvent::VERSION.to_f >= 0.4 : false
      rescue LoadError
        false
      end
    end

    def rb_inotify?
      begin
        require 'rb-inotify'
        if defined?(INotify::VERSION)
          version = INotify::VERSION
          version[0] > 0 || version[1] >= 6
        end
      rescue LoadError
        false
      end
    end

    def use_block(context, block)
      return if block.nil?
      if block.arity == 1
        block.call(context)
      else
        context.instance_eval(&block)
      end
    end

  end
end
