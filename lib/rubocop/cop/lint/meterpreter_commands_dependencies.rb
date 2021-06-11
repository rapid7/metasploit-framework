module RuboCop
  module Cop
    module Lint
      # `array.any?` is a simplified way to say `!array.empty?`
      #
      # @example
      #   # bad
      #   !array.empty?
      #
      #   # good
      #   array.any?
      class MeterpreterCommandDependencies < Base
        MSG = 'Convert meterpreter api calls into meterpreter command dependencies.'.freeze

        def_node_matcher :file_rm_call?, <<~PATTERN
          (send (send (send (send nil? :client) :fs) :file) :rm)
        PATTERN

        def_node_matcher :file_ls_call?, <<~PATTERN
          (send (send (send (send nil? :client) :fs) :file) :ls)
        PATTERN

        def_node_matcher :command_list?, <<~PATTERN
          (lvasgn :commands
            _)
        PATTERN

        extend AutoCorrector

        def on_new_investigation
          super
          @current_commands = [] # TODO: Not sure if I need to keep track of current commands, as I can just add all to latest and rewrite the list
          @latest_commands = []
          @command_list_node = nil
          require "pry"; binding.pry
        end

        def on_investigation_end
          super
          require "pry"; binding.pry
          if @command_list_node.nil?
            # Handle this error
          else
            add_offense(@command_list_node, &autocorrector)
          end
        end

        def on_lvasgn(node)
          return unless command_list?(node)
          @command_list_node = node
          # TODO: Extract out the current list of commands from the node
          require "pry"; binding.pry
        end

        def on_send(node)
          require "pry"; binding.pry
          if file_rm_call?(node)
            unless @latest_commands.include?('stdapi_fs_rm')
              @latest_commands << 'stdapi_fs_rm'
              # Add an offense, but don't provide an autocorrect. There will be a final autocorrect to fix all issues
              add_offense(node)
            end
          end

          if file_ls_call?(node)
            unless @latest_commands.include?('stdapi_fs_ls')
              @latest_commands << 'stdapi_fs_ls'
              # Add an offense, but don't provide an autocorrect. There will be a final autocorrect to fix all issues
              add_offense(node)
            end
          end
        end

        def autocorrector
          lambda do |corrector|
            require "pry"; binding.pry
            puts "Are we here? #{@latest_commands} #{@command_list_node.inspect}"
            if @command_list_node.nil?
              # TODO: Handle this error
            else
              # TODO: Need to build out the formatting for adding the full method.

              header = %w[
                def initialize(info = {})
                  super(
                    update_info(
                      info,
                      'Compat' => {
                        'Meterpreter' => {
                          'Commands' => %w
                          ]
              footer = %w[
                        }
                      }
                    )
                  )
                          ]
              # TODO: Look into using a AST to check if an inialise already exits and then look into more consistent code to anchor off. e.g. adding after 'SessionTypes'
              @latest_commands = @latest_commands.uniq.sort

              # TODO: WE should replace just the array contents, not the entire array
              corrector.replace(@command_list_node, "#{header.join("\n")}#{@latest_commands.join("\n")}#{footer.join("\n")}]")

            end
          end
        end
      end
    end
  end
end





# module RuboCop
#   module Cop
#     module Lint
#       class MeterpreterCommandsDependencies < Base
#         extend AutoCorrector
#
#         MSG = 'Scans modules for meterpreter commands, adds new method to define these commands to each corresponding module: '.freeze
#
#         # TODO: calls can be made by either `client.` or `session.`, need to handle both
#         def_node_matcher :config_sysinfo_call?, <<~PATTERN
#           (send (send (send (send nil? :session) :sys) :config) :sysinfo)
#         PATTERN

        # def_node_matcher :railgun_call?, <<~PATTERN
        #   (send (send (send nil :client) :railgun) ...)
        # PATTERN
        #
        # def_node_matcher :fs_dir_getwd_call?, <<~PATTERN
        #   (send (send (send (send nil :session) :fs) :dir) :getwd)
        # PATTERN
        #
        # def_node_matcher :fs_file_rm_call?, <<~PATTERN
        #   (send (send (send (send nil :session) :fs) :file) :rm)
        # PATTERN
        #
        # def_node_matcher :appapi_app_install_call?, <<~PATTERN
        #   (send (send (send nil :session) :appapi) :app_install)
        # PATTERN
        #
        # def_node_matcher :process_execute_call?, <<~PATTERN
        #   (send (send (send (send nil :session) :sys) :process) :execute)
        # PATTERN
        #
        # def_node_matcher :fs_file_stat_call?, <<~PATTERN
        #   (send (send (send (send nil :session) :fs) :file) :stat)
        # PATTERN
        #
        # def_node_matcher :get_processes_call?, <<~PATTERN
        #   (send (send (send (send nil :session) :sys) :process) :get_processes)
        # PATTERN
        #
        # def_node_matcher :config_getenv_call?, <<~PATTERN
        #   (send (send (send (send nil :session) :sys) :config) :getenv)
        # PATTERN
        #
        # def_node_matcher :process_open_call?, <<~PATTERN
        #   (send (send (send (send nil :client) :sys) :process) :open)
        # PATTERN
        #
        # def_node_matcher :config_getprivs_call?, <<~PATTERN
        #   (send (send (send (send nil :client) :sys) :config) :getprivs)
        # PATTERN
        #
        # def_node_matcher :process_getpid_call?, <<~PATTERN
        #   (send (send (send (send nil :session) :sys) :process) :getpid)
        # PATTERN
        #
        # def_node_matcher :process_kill_call?, <<~PATTERN
        #   (send (send (send (send nil :session) :sys) :process) :kill)
        # PATTERN
        #
        # def_node_matcher :fs_dir_rmdir_call?, <<~PATTERN
        #   (send (send (send (send nil :session) :fs) :dir) :rmdir)
        # PATTERN
        #
        # def_node_matcher :fs_dir_mkdir_call?, <<~PATTERN
        #   (send (send (send (send nil :session) :fs) :dir) :mkdir)
        # PATTERN
        #
        # def_node_matcher :fs_file_copy_call?, <<~PATTERN
        #   (send (send (send (send nil :session) :fs) :file) :copy)
        # PATTERN
        #
        # def_node_matcher :config_getdrivers_call?, <<~PATTERN
        #   (send (send (send (send nil :client) :sys) :config) :getdrivers)
        # PATTERN
        #
        # def_node_matcher :config_getuid_call?, <<~PATTERN
        #   (send (send (send (send nil :session) :sys) :config) :getuid)
        # PATTERN
        #
        # def_node_matcher :config_getsid_call?, <<~PATTERN
        #   (send (send (send (send nil :client) :sys) :config) :getsid)
        # PATTERN
        #
        # def_node_matcher :config_is_system_call?, <<~PATTERN
        #   (send (send (send (send nil :client) :sys) :config) :is_system)
        # PATTERN
        #
        # def_node_matcher :fs_file_md5_call?, <<~PATTERN
        #   (send (send (send (send nil :client) :fs) :file) :md5)
        # PATTERN
        #
        # def_node_matcher :powershell_execute_string_call?, <<~PATTERN
        #   (send (send (send nil :client) :powershell) :execute_string)
        # PATTERN
        #
        # def_node_matcher :power_reboot_call?, <<~PATTERN
        #   (send (send (send (send nil :session) :sys) :power) :reboot)
        # PATTERN
        #
        # def_node_matcher :processes_call?, <<~PATTERN
        #   (send (send (send (send nil :session) :sys) :process) :processes)
        # PATTERN
        #
        # def_node_matcher :lanattacks_dhcp_reset_call?, <<~PATTERN
        #   (send (send (send nil :client) :lanattacks) ...)
        # PATTERN


        # def on_send(node)
        #
        #   # TODO: I think an array here that just gets appended too would be the right call
        #   #   then just loop over it at the end.
        #   expression = config_sysinfo_call?(node)
        #   return unless expression
        #
        #   add_offense(node) do |corrector|
        #     corrector.replace(node, "stdapi_sys_config_sysinfo")
        #   end

          # if raligun_call?(node)
          #   dependencies_list << 'stdapi_ralilgun_*'
          # end
          #
          # if fs_dir_getwd_call?(node)
          #   dependencies_list << 'stdapi_fs_getwd'
          # end
          #
          # if fs_file_rm_call?(node)
          #   dependencies_list << 'stdapi_fs_rm'
          # end
          #
          # if appapi_app_install_call?(node)
          #   dependencies_list << 'appapi_app_install'
          # end
          #
          # if process_execute_call?(node)
          #   dependencies_list << 'stdapi_sys_process_execute'
          # end
          #
          # if fs_file_stat_call?(node)
          #   dependencies_list << 'stdapi_fs_stat'
          # end
          #
          # if get_processes_call?(node)
          #   dependencies_list << 'stdapi_sys_process_get_processes'
          # end
          #
          # if config_getenv_call?(node)
          #   dependencies_list << 'stdapi_sys_config_getenv'
          # end
          #
          # if process_open_call?(node)
          #   dependencies_list << 'stdapi_sys_process_open'
          # end
          #
          # if net_socket_create_call?(node)
          #   dependencies_list << 'stdapi_net_create'
          # end
          #
          # if config_getprivs_call?(node)
          #   dependencies_list << 'sys_config_getprivs'
          # end
          #
          # if process_getpid_call?(node)
          #   dependencies_list << 'stdapi_sys_process_getpid'
          # end
          #
          # if process_kill_call?(node)
          #   dependencies_list << 'stdapi_sys_process_kill'
          # end
          #
          # if fs_dir_rmdir_call?(node)
          #   dependencies_list << 'stdapi_fs_rmdir'
          # end
          #
          # if fs_dir_mkdir_call?(node)
          #   dependencies_list << 'stdapi_fs_mkdir'
          # end
          #
          # if fs_file_copy_call?(node)
          #   dependencies_list << 'stdapi_fs_cp'
          # end
          #
          # if config_getdrivers_call?(node)
          #   dependencies_list << 'sys_config_getdrivers'
          # end
          #
          # if config_getuid_call?(node)
          #   dependencies_list << 'sys_config_getuid'
          # end
          #
          # if config_getsid_call?(node)
          #   dependencies_list << 'sys_config_getsid'
          # end
          #
          # if config_is_system_call?(node)
          #   dependencies_list << 'sys_config_is_system'
          # end
          #
          # if fs_file_md5_call?(node)
          #   dependencies_list << 'stdapi_fs_md5'
          # end
          #
          # if powershell_execute_string_call?(node)
          #   dependencies_list << 'powershell_execute_string'
          # end
          #
          # if power_reboot_call?(node)
          #   dependencies_list << 'stdapi_sys_power_reboot'
          # end
          #
          # if processes_call?(node)
          #   dependencies_list << 'stdapi_sys_processes'
          # end
          #
          # if lanattacks_dhcp_reset_call?(node)
          #   dependencies_list << 'lanattacks_*'
          # end


          # add_offense(node) do |corrector|
          #   corrector.replace(node, "#{dependencies_list}")
          # end
#         end
#       end
#     end
#   end
# end

# TODO: Code needs to identify what the module currenlty has:
#       IF modulde has an initialise method and info already in place, add the following code
# ```
# 'Compat' => {
#           'Meterpreter' => {
#             'Commands' => %w[
#               core_channel_*
#               stdapi_fs_stat
#               stdapi_fs_rm
#               stdapi_fs_rmdir
#               stdapi_fs_pwd
#               stdapi_fs_shell_command_token
#             ]
# ```
#
# OR
#
# TODO: IF modulde has an NO initialise method add the following code -- SORTED AND UNIQUE list
# ```
#   def initialize(info = {})
#     super(
#       update_info(
#         info,
#         'Compat' => {
#           'Meterpreter' => {
#             'Commands' => %w[
#               core_channel_*
#               stdapi_fs_stat
#               stdapi_fs_rm
#               stdapi_fs_rmdir
#               stdapi_fs_pwd
#               stdapi_fs_shell_command_token
#             ]
#           }
#         }
#       )
#     )

# TODO: List of calls I'm unsure what api needs to be called/I dont believe need to be called :
#   - session.core.load_library
#   - session.ext.aliases.include
#   - session.fs.file.open
#   - session.type.eql
#   - session.ext.aliases.include
#   - client.core.use
#   - session.fs.file.new
#   - session.tunnel_peer.split
