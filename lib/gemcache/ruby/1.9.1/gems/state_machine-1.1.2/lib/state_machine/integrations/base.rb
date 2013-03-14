module StateMachine
  module Integrations
    # Provides a set of base helpers for managing individual integrations
    module Base
      module ClassMethods
        # The default options to use for state machines using this integration
        attr_reader :defaults
        
        # The name of the integration
        def integration_name
          @integration_name ||= begin
            name = self.name.split('::').last
            name.gsub!(/([A-Z]+)([A-Z][a-z])/,'\1_\2')
            name.gsub!(/([a-z\d])([A-Z])/,'\1_\2')
            name.downcase!
            name.to_sym
          end
        end
        
        # Whether this integration is available for the current library.  This
        # is only true if the ORM that the integration is for is currently
        # defined.
        def available?
          matching_ancestors.any? && Object.const_defined?(matching_ancestors[0].split('::')[0])
        end
        
        # The list of ancestor names that cause this integration to matched.
        def matching_ancestors
          []
        end
        
        # Whether the integration should be used for the given class.
        def matches?(klass)
          matches_ancestors?(klass.ancestors.map {|ancestor| ancestor.name})
        end
        
        # Whether the integration should be used for the given list of ancestors.
        def matches_ancestors?(ancestors)
          (ancestors & matching_ancestors).any?
        end
        
        # Tracks the various version overrides for an integration
        def versions
          @versions ||= []
        end
        
        # Creates a new version override for an integration.  When this
        # integration is activated, each version that is marked as active will
        # also extend the integration.
        # 
        # == Example
        # 
        #   module StateMachine
        #     module Integrations
        #       module ORMLibrary
        #         version '0.2.x - 0.3.x' do
        #           def self.active?
        #             ::ORMLibrary::VERSION >= '0.2.0' && ::ORMLibrary::VERSION < '0.4.0'
        #           end
        #           
        #           def invalidate(object, attribute, message, values = [])
        #             # Override here...
        #           end
        #         end
        #       end
        #     end
        #   end
        # 
        # In the above example, a version override is defined for the ORMLibrary
        # integration when the version is between 0.2.x and 0.3.x.
        def version(name, &block)
          versions << mod = Module.new(&block)
          mod
        end
        
        # The path to the locale file containing translations for this
        # integration.  This file will only exist for integrations that actually
        # support i18n.
        def locale_path
          path = "#{File.dirname(__FILE__)}/#{integration_name}/locale.rb"
          path if File.exists?(path)
        end
        
        # Extends the given object with any version overrides that are currently
        # active
        def extended(base)
          versions.each do |version|
             base.extend(version) if version.active?
          end
        end
      end
      
      extend ClassMethods
      
      def self.included(base) #:nodoc:
        base.class_eval { extend ClassMethods }
      end
    end
  end
end
