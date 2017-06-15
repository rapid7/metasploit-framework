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
        if ::File.exist?(path)
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
  # Maps legacy Meterpreter script names to replacement post modules
  #
  def legacy_script_to_post_module(script_name)
    {
      'autoroute' => 'post/multi/manage/autoroute',
      'checkvm' => 'post/windows/gather/checkvm',
      'duplicate' => 'post/windows/manage/multi_meterpreter_inject',
      'enum_chrome' => 'post/windows/gather/enum_chrome',
      'enum_firefox' => 'post/windows/gather/enum_firefox',
      'enum_logged_on_users' => 'post/windows/gather/enum_logged_on_users',
      'enum_powershell_env' => 'post/windows/gather/enum_powershell_env',
      'enum_putty' => 'post/windows/gather/enum_putty_saved_sessions',
      'enum_shares' => 'post/windows/gather/enum_shares',
      'file_collector' => 'post/windows/gather/enum_files',
      'get_application_list' => 'post/windows/gather/enum_applications',
      'get_filezilla_creds' => 'post/windows/gather/credentials/filezilla_server',
      'get_local_subnets' => 'post/multi/manage/autoroute',
      'get_valid_community' => 'post/windows/gather/enum_snmp',
      'getcountermeasure' => 'post/windows/manage/killav',
      'getgui' => 'post/windows/manage/enable_rdp',
      'getvncpw' => 'post/windows/gather/credentials/vnc',
      'hashdump' => 'post/windows/gather/smart_hashdump',
      'hostsedit' => 'post/windows/manage/inject_host',
      'keylogrecorder' => 'post/windows/capture/keylog_recorder',
      'killav' => 'post/windows/manage/killav',
      'metsvc' => 'post/windows/manage/persistence_exe',
      'migrate' => 'post/windows/manage/migrate',
      'packetrecorder' => 'post/windows/manage/rpcapd_start',
      'persistence' => 'post/windows/manage/persistence_exe',
      'prefetchtool' => 'post/windows/gather/enum_prefetch',
      'remotewinenum' => 'post/windows/gather/wmic_command',
      'schelevator' => 'exploit/windows/local/ms10_092_schelevator',
      'screen_unlock' => 'post/windows/escalate/screen_unlock',
      'screenspy' => 'post/windows/gather/screen_spy',
      'search_dwld' => 'post/windows/gather/enum_files',
      'service_permissions_escalate' => 'exploits/windows/local/service_permissions',
      'uploadexec' => 'post/windows/manage/download_exec',
      'webcam' => 'post/windows/manage/webcam',
      'wmic' => 'post/windows/gather/wmic_command',
    }[script_name]
  end

  #
  # Executes the supplied script, Post module, or local Exploit module with
  #   arguments +args+
  #
  # Will search the script path.
  #
  def execute_script(script_name, *args)
    post_module = legacy_script_to_post_module(script_name)

    if post_module
      print_warning("Meterpreter scripts are deprecated. Try #{post_module}.")
      print_warning("Example: run #{post_module} OPTION=value [...]")
    end

    mod = framework.modules.create(script_name)
    if mod
      # Don't report module run events here as it will be taken care of
      # in +Post.run_simple+
      opts = { 'SESSION' => self.sid }
      args.each do |arg|
        k,v = arg.split("=", 2)
        # case doesn't matter in datastore, but it does in hashes, let's normalize
        opts[k.downcase] = v
      end
      if mod.type == "post"
        mod.run_simple(
          # Run with whatever the default stance is for now.  At some
          # point in the future, we'll probably want a way to force a
          # module to run in the background
          #'RunAsJob' => true,
          'LocalInput'  => self.user_input,
          'LocalOutput' => self.user_output,
          'Options'     => opts
        )
      elsif mod.type == "exploit"
        # well it must be a local, we're not currently supporting anything else
        if mod.exploit_type == "local"
          # get a copy of the session exploit's datastore if we can
          original_exploit_datastore = self.exploit.datastore || {}
          copy_of_orig_exploit_datastore = original_exploit_datastore.clone
          # convert datastore opts to a hash to normalize casing issues
          local_exploit_opts = {}
          copy_of_orig_exploit_datastore.each do |k,v|
            local_exploit_opts[k.downcase] = v
          end
          # we don't want to inherit a couple things, like AutoRunScript's
          to_neuter = %w{AutoRunScript InitialAutoRunScript LPORT TARGET}
          to_neuter.each do |setting|
            local_exploit_opts.delete(setting.downcase)
          end

          # merge in any opts that were passed in, defaulting all other settings
          # to the values from the datastore (of the exploit) that spawned the
          # session
          local_exploit_opts = local_exploit_opts.merge(opts)

          new_session = mod.exploit_simple(
            'Payload'       => local_exploit_opts.delete('payload'),
            'Target'        => local_exploit_opts.delete('target'),
            'LocalInput'    => self.user_input,
            'LocalOutput'   => self.user_output,
            'Options'       => local_exploit_opts
            )

        end # end if local
      end # end if exploit

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
