dir = File.expand_path(File.dirname(__FILE__))
$LOAD_PATH.unshift dir unless $LOAD_PATH.include?(dir)

require 'thread'

module FSSM
  
  FSSMError         = Class.new(StandardError)
  FileNotFoundError = Class.new(FSSMError)
  FileNotRealError  = Class.new(FSSMError)
  CallbackError     = Class.new(FSSMError)
  
  autoload :VERSION,        'fssm/version'
  autoload :Pathname,       'fssm/pathname'
  autoload :Support,        'fssm/support'
  autoload :Tree,           'fssm/tree'
  autoload :Path,           'fssm/path'
  autoload :Monitor,        'fssm/monitor'
  
  module State
    autoload :Directory,    'fssm/state/directory'
    autoload :File,         'fssm/state/file'
  end
  
  module Backends
    autoload :Polling,      'fssm/backends/polling'
    autoload :FSEvents,     'fssm/backends/fsevents'
    autoload :RBFSEvent,    'fssm/backends/rbfsevent'
    autoload :Inotify,      'fssm/backends/inotify'
    
    class << self
      def set_backend(const_symbol=nil, value=nil)
        const_symbol ||= :Default
        value ||= ::FSSM::Support.backend
        
        if (value.is_a?(Symbol) || value.is_a?(String))
          unless const_defined?(value)
            raise NameError,
              "uninitialized constant FSSM::Backends::#{value}"
          end
          value = const_get(value)
        end
        
        unless value.is_a?(Class)
          raise ArgumentError,
            "value must be a class or the symbol of an existing backend"
        end
        
        remove_const(const_symbol) if const_defined?(const_symbol)
        const_set(const_symbol, value)
      end
      
      def const_missing(symbol)
        symbol == :Default ? set_backend(symbol, FSSM::Support.backend) : super
      end
      
    end
  end
 
  class << self
    def dbg(msg=nil)
      STDERR.puts("FSSM -> #{msg}")
    end

    def monitor(*args, &block)
      options = args[-1].is_a?(Hash) ? args.pop : {}
      monitor = FSSM::Monitor.new(options)
      FSSM::Support.use_block(args.empty? ? monitor : monitor.path(*args), block)

      monitor.run
    end
  end
  
end

STDERR.puts "\nDear developers making use of FSSM in your projects,\n"
STDERR.puts "FSSM is essentially dead at this point. Further development will"
STDERR.puts "be taking place in the new shared guard/listen project. Please"
STDERR.puts "let us know if you need help transitioning! ^_^b\n"
STDERR.puts "- Travis Tilley\n\n"
