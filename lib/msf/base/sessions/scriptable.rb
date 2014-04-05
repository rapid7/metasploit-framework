# -*- coding: binary -*-

module Msf::Session

module Scriptable

  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods
    #
    # If the +script+ exists, return its path. Otherwise return nil
    #
    def find_script_path(script)
      # Find the full file path of the specified argument
      check_paths =
        [
          script,
          ::File.join(script_base, "#{script}"),
          ::File.join(script_base, "#{script}.rb"),
          ::File.join(user_script_base, "#{script}"),
          ::File.join(user_script_base, "#{script}.rb")
        ]

      full_path = nil

      # Scan all of the path combinations
      check_paths.each { |path|
        if ::File.exists?(path)
          full_path = path
          break
        end
      }

      full_path
    end
    def script_base
      ::File.join(Msf::Config.script_directory, self.type)
    end
    def user_script_base
      ::File.join(Msf::Config.user_script_directory, self.type)
    end

  end

  #
  # Override
  #
  def execute_file
    raise NotImplementedError
  end

  #
  # Executes the supplied script or Post module with arguments +args+
  #
  # Will search the script path.
  #
  def execute_script(script_name, *args)
    mod = framework.modules.create(script_name)
    if (mod and mod.type == "post")
      # Don't report module run events here as it will be taken care of
      # in +Post.run_simple+
      opts = { 'SESSION' => self.sid }
      args.each do |arg|
        k,v = arg.split("=", 2)
        opts[k] = v
      end
      mod.run_simple(
        # Run with whatever the default stance is for now.  At some
        # point in the future, we'll probably want a way to force a
        # module to run in the background
        #'RunAsJob' => true,
        'LocalInput'  => self.user_input,
        'LocalOutput' => self.user_output,
        'Options'     => opts
      )
    else
      full_path = self.class.find_script_path(script_name)

      # No path found?  Weak.
      if full_path.nil?
        print_error("The specified script could not be found: #{script_name}")
        return true
      end
      framework.events.on_session_script_run(self, full_path)
      execute_file(full_path, args)
    end
  end

end

end

