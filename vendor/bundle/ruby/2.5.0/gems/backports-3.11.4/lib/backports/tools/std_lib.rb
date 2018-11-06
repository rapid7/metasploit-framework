module Backports
  module StdLib
    class LoadedFeatures
      if RUBY_VERSION >= "1.9"
        # Full paths are recorded in $LOADED_FEATURES.
        @@our_loads = {}
        # Check loaded features for one that matches "#{any of the load path}/#{feature}"
        def include?(feature)
          return true if @@our_loads[feature]
          # Assume backported features are Ruby libraries (i.e. not C)
          @loaded ||= $LOADED_FEATURES.group_by{|p| File.basename(p, ".rb")}
          if fullpaths = @loaded[File.basename(feature, ".rb")]
            fullpaths.any?{|fullpath|
              base_dir, = fullpath.partition("/#{feature}")
              $LOAD_PATH.include?(base_dir)
            }
          end
        end

        def self.mark_as_loaded(feature)
          @@our_loads[feature] = true
          # Nothing to do, the full path will be OK
        end

      else
        # Requested features are recorded in $LOADED_FEATURES
        def include?(feature)
          # Assume backported features are Ruby libraries (i.e. not C)
          $LOADED_FEATURES.include?("#{File.basename(feature, '.rb')}.rb")
        end

        def self.mark_as_loaded(feature)
          $LOADED_FEATURES << "#{File.basename(feature, '.rb')}.rb"
        end
      end
    end

    class << self
      attr_accessor :extended_lib

      def extend_relative relative_dir="stdlib"
        loaded = Backports::StdLib::LoadedFeatures.new
        dir = File.expand_path(relative_dir, File.dirname(caller.first.split(/:\d/,2).first))
        Dir.entries(dir).
          map{|f| Regexp.last_match(1) if /^(.*)\.rb$/ =~ f}.
          compact.
          each do |f|
            path = File.expand_path(f, dir)
            if loaded.include?(f)
              require path
            else
              @extended_lib[f] << path
            end
          end
      end
    end
    self.extended_lib ||= Hash.new{|h, k| h[k] = []}
  end
end
