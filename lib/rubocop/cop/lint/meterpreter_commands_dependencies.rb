require 'rex/post/meterpreter/command_mapper'

module RuboCop
  module Cop
    module Lint
      class MeterpreterCommandDependencies < Base
        extend AutoCorrector
        include Alignment

        MSG = 'Convert meterpreter api calls into meterpreter command dependencies.'.freeze
        MISSING_METHOD_CALL_FOR_COMMAND_MSG = 'Compatibility command does not have an associated method call.'.freeze
        COMMAND_DUPLICATED_MSG = 'Command duplicated.'.freeze

        CLIENT_OR_SESSION = '{(lvar {:session :client}) (send nil? {:session :client})}'.freeze
        # Since a created process can have any name, match on anything
        PROCESS = '{(lvar _) (send nil? _)}'.freeze
        # Covering calls that are made with `self.`
        SELF = '(self)'.freeze

        # Matchers for identifying what is current present in each module, so we can append required section at a later point
        def_node_matcher :find_nested_update_info_node, <<~PATTERN
          (def :initialize _args (begin (super (send nil? {:update_info :merge_info} (lvar :info) $(hash ...))) ...))
        PATTERN

        def_node_matcher :find_update_info_node, <<~PATTERN
          (def :initialize _args (super (send nil? {:update_info :merge_info} (lvar :info) $(hash ...)) ...))
        PATTERN

        def_node_matcher :find_nested_info_node, <<~PATTERN
          (def :initialize _args (super $(hash ...) ...))
        PATTERN

        def_node_matcher :find_info_node, <<~PATTERN
          (def :initialize _args (begin (super $(hash ...)) ...))
        PATTERN

        def_node_matcher :find_command_array_node, <<~PATTERN
          (hash (pair (str "Commands") $(array ...)))
        PATTERN

        def_node_matcher :initialize_present?, <<~PATTERN
          (def :initialize __)
        PATTERN

        def_node_matcher :super_present?, <<~PATTERN
          (begin (zsuper) ...)
        PATTERN

        class StackFrame
          # Keeps track of nodes of interest
          attr_accessor :nodes
          # Keeps track of the visiting state, i.e. what we'll do next when we visit particular nodes
          attr_accessor :visiting_state

          # The list of commands identified in this stack frame
          attr_accessor :identified_commands

          def initialize
            @nodes = {}
            @visiting_state = :none
            @identified_commands = []
          end

          # The currently registered commands
          def current_commands
            commands = []
            return commands unless nodes[:commands_node]

            nodes[:commands_node].value.each_child_node do |command|
              commands << command.value
            end

            commands
          end
        end

        def on_module(node)
          enter_frame(node)
        end

        def after_module(node)
          leave_frame(node)
        end

        def on_class(node)
          enter_frame(node)
        end

        def after_class(node)
          leave_frame(node)
        end

        # Allows us to handle scenarios of a module having multiple classes or modules present
        def enter_frame(node)
          # Frames can't be nested
          if @current_frame
            return
          end

          @current_frame = StackFrame.new
          nodes[:investigated_node] = node
        end

        def subtract_arrays_and_leave_duplicates(first, second)
          result = first.clone
          second.each do |value|
            index = result.index(value)
            if index
              result.delete_at(index)
            end
          end
          result
        end

        def leave_frame(node)
          unless nodes[:investigated_node] == node
            return
          end

          # Ensure commands are sorted and unique
          @current_frame.identified_commands = @current_frame.identified_commands.uniq.sort

          # Calculate invalid values, but leave duplicates around so that they can be highlighted as being invalid
          invalid_current_commands = subtract_arrays_and_leave_duplicates(@current_frame.current_commands, @current_frame.identified_commands)
          if invalid_current_commands.any? && nodes[:commands_node]
            nodes[:commands_node].value.each_child_node do |command_node|
              command = command_node.source
              is_missing_call = !@current_frame.identified_commands.include?(command)
              has_duplicate_calls = (
                @current_frame.current_commands.select { |c| c == command }.count > 1
              )
              if is_missing_call
                add_offense(command_node, message: MISSING_METHOD_CALL_FOR_COMMAND_MSG)
              elsif has_duplicate_calls
                add_offense(command_node, message: COMMAND_DUPLICATED_MSG)
              end
            end
          end

          if @current_frame.identified_commands.empty? && invalid_current_commands.empty?
            @current_frame = nil
            return
          elsif nodes[:compat_node] && nodes[:meterpreter_node] && nodes[:commands_node] && @current_frame.identified_commands == @current_frame.current_commands
            # Happy path
            @current_frame = nil
            return
          elsif nodes[:compat_node] && nodes[:meterpreter_node] && nodes[:commands_node] && @current_frame.identified_commands != @current_frame.current_commands
            add_offense(nodes[:commands_node], &autocorrector)
          elsif nodes[:compat_node] && nodes[:meterpreter_node] && nodes[:commands_node].nil?
            add_offense(nodes[:meterpreter_node], &autocorrector)
          elsif nodes[:compat_node] && nodes[:meterpreter_node].nil? && nodes[:commands_node].nil?
            add_offense(nodes[:compat_node], &autocorrector)
          elsif nodes[:initialize_node] && nodes[:super_node] && nodes[:info_node].nil?
            add_offense(nodes[:super_node].children.first, &autocorrector)
          elsif nodes[:compat_node].nil? && nodes[:meterpreter_node].nil? && nodes[:commands_node].nil? && !nodes[:initialize_node].nil?
            add_offense(nodes[:info_node].children.last, &autocorrector)
          elsif nodes[:initialize_node].nil?
            add_offense(nodes[:investigated_node].identifier, &autocorrector)
          else
            raise 'Scenario not handled'
          end

          @current_frame = nil
        end

        def on_def(node)
          return unless visiting_state == :none

          if initialize_present?(node)
            nodes[:initialize_node] = node
          end

          update_info_node = (
            find_update_info_node(node) ||
              find_nested_update_info_node(node) ||
              find_info_node(node) ||
              find_nested_info_node(node)
          )
          return if update_info_node.nil?

          nodes[:info_node] = update_info_node

          self.visiting_state = :looking_for_hash_keys
        end

        def after_def(_node)
          if visiting_state == :looking_for_hash_keys
            self.visiting_state = :finished
          end
        end

        def on_begin(node)
          if super_present?(node)
            nodes[:super_node] = node
          end
        end

        def visiting_state
          @current_frame&.visiting_state || :none
        end

        def visiting_state=(state)
          @current_frame.visiting_state = state
        end

        def nodes
          @current_frame.nodes
        end

        def on_pair(node)
          return unless visiting_state == :looking_for_hash_keys

          if node.key.value == 'Compat'
            nodes[:compat_node] = node
          elsif node.key.value == 'Meterpreter'
            nodes[:meterpreter_node] = node
          elsif node.key.value == 'Commands'
            nodes[:commands_node] = node
          end
        end

        def hash_arg?(node)
          node.type == :hash
        end

        # Generates AST matchers based upon Meterpreter API calls.
        def node_pattern_for(value)
          split_values = value.split('.')
          split_values_length = split_values.length

          node_matcher = '(send ' * (split_values_length - 1)

          target, *methods = split_values
          if target == 'session' || target == 'client'
            node_matcher << CLIENT_OR_SESSION
          elsif target == 'process'
            node_matcher << PROCESS
          elsif target == 'self'
            node_matcher << SELF
          else
            raise "Unknown target in expression #{value}"
          end

          methods.each do |element|
            node_matcher << ' :' + element + ' _*)'
          end

          NodePattern.new(node_matcher)
        end

        # Maps each Meterpreter API call to a command.
        def mappings
          return @mappings if @mappings

          # Expressions to commands
          expressions_to_commands = {
            'session.fs.file.upload': [
              'stdapi_fs_separator',
              'core_channel_open',
              'core_channel_write',
              'core_channel_tell',
              'core_channel_close'
            ],

            'session.fs.file.upload_file': [
              'core_channel_open',
              'core_channel_write',
              'core_channel_tell',
              'core_channel_close'
            ],

            'session.fs.file.download': [
              'core_channel_open',
              'stdapi_fs_stat',
              'core_channel_read',
              'core_channel_eof',
              'core_channel_close'
            ],

            'session.fs.file.download_file': [
              'core_channel_open',
              'stdapi_fs_stat',
              'core_channel_read',
              'core_channel_eof',
              'core_channel_close'
            ],
            "session.fs.file.new": [
              'core_channel_open',
              'core_channel_read',
              'core_channel_write',
              'core_channel_eof'
            ]
          }

          # Commands to expressions
          core_channel_ids = {
            core_channel_close: [
            ],
            core_channel_eof: [
            ],
            core_channel_interact: [
            ],
            core_channel_open: [
              'client.net.socket.create'
            ],
            core_channel_read: [
            ],
            core_channel_seek: [
            ],
            core_channel_tell: [
            ],
            core_channel_write: [
              'session.fs.file.new'
            ],
            core_console_write: [
            ],
            core_enumextcmd: [
            ],
            core_get_session_guid: [
            ],
            core_loadlib: [
              'session.core.load_library'
            ],
            core_machine_id: [
              'client.core.machine_id'
            ],
            core_migrate: [
              'session.core.migrate'
            ],
            core_native_arch: [
              'self.core.native_arch',
              'client.native_arch'
            ],
            core_negotiate_tlv_encryption: [
              'session.core.negotiate_tlv_encryption'
            ],
            core_patch_url: [
            ],
            core_pivot_add: [
            ],
            core_pivot_remove: [
            ],
            core_pivot_session_died: [
            ],
            core_set_session_guid: [
              'session.core.set_session_guid'
            ],
            core_set_uuid: [
              'self.core.set_uuid'
            ],
            core_shutdown: [
              'session.core.shutdown'
            ],
            core_transport_add: [
              'client.core.transport_add'
            ],
            core_transport_change: [
              'session.core.transport_change'
            ],
            core_transport_getcerthash: [
            ],
            core_transport_list: [
              'client.core.transport_list'
            ],
            core_transport_next: [
              'client.core.transport_next'
            ],
            core_transport_prev: [
              'client.core.transport_prev'
            ],
            core_transport_remove: [
              'client.core.transport_remove'
            ],
            core_transport_setcerthash: [
            ],
            core_transport_set_timeouts: [
            ],
            core_transport_sleep: [
              'client.core.transport_sleep'
            ],
            core_pivot_session_new: [
            ]
          }

          stdapi_command_ids = {
            stdapi_fs_chdir: [
              'session.fs.dir.chdir'
            ],
            stdapi_fs_chmod: [
              'session.fs.file.chmod'
            ],
            stdapi_fs_delete_dir: [
              'session.fs.dir.rmdir'
            ],
            stdapi_fs_delete_file: [
              'session.fs.file.rm',
              'session.fs.file.delete'
            ],
            stdapi_fs_file_copy: [
              'session.fs.file.copy'
            ],
            stdapi_fs_file_expand_path: [
              'client.fs.file.expand_path'
            ],
            stdapi_fs_file_move: [
              'session.fs.file.mv'
            ],
            stdapi_fs_getwd: [
              'session.fs.dir.getwd',
              'client.fs.dir.getwd',
              'client.fs.dir.pwd'
            ],
            stdapi_fs_ls: [
              'session.fs.file.ls',
              'client.fs.dir.entries',
              'client.fs.dir.entries_with_info',
              'client.fs.dir.match'
            ],
            stdapi_fs_md5: [
              'client.fs.file.md5'
            ],
            stdapi_fs_mkdir: [
              'client.fs.dir.mkdir'
            ],
            stdapi_fs_mount_show: [
              'client.fs.mount.show_mount'
            ],
            stdapi_fs_search: [
              'client.fs.file.search'
            ],
            stdapi_fs_separator: [
              'session.fs.file.separator'
            ],
            stdapi_fs_sha1: [
              'session.fs.file.sha1'
            ],
            stdapi_fs_stat: [
              'client.fs.file.exist?',
              'session.fs.file.stat',
            ],
            stdapi_net_config_add_route: [
              'client.net.config.add_route'
            ],
            stdapi_net_config_get_arp_table: [
              'client.net.config.arp_table',
              'client.net.config.get_arp_table'
            ],
            stdapi_net_config_get_interfaces: [
              'session.net.config.each_interface',
            ],
            stdapi_net_config_get_netstat: [
              'client.net.config.netstat',
              'client.net.config.get_netstat'
            ],
            stdapi_net_config_get_proxy: [
              'client.net.config.get_proxy_config'
            ],
            stdapi_net_config_get_routes: [
              'client.net.config.each_route',
            ],
            stdapi_net_config_remove_route: [
              'client.net.config.remove_route'
            ],
            stdapi_net_resolve_host: [
              'client.net.resolve.resolve_host'
            ],
            stdapi_net_resolve_hosts: [
              'client.net.resolve.resolve_hosts'
            ],
            stdapi_net_socket_tcp_shutdown: [
            ],
            stdapi_net_tcp_channel_open: [
            ],
            "stdapi_railgun_*": [
              'client.railgun.memread',
              'session.railgun.memwrite',
              'session.railgun.util'
            ],
            "stdapi_railgun_api*": [
              'client.railgun'
            ],
            stdapi_registry_check_key_exists: [
              'client.sys.registry.check_key_exists'
            ],
            stdapi_registry_close_key: [
              'client.sys.registry.close_key'
            ],
            stdapi_registry_create_key: [
              'session.sys.registry.create_key'
            ],
            stdapi_registry_delete_key: [
              'session.sys.registry.delete_key'
            ],
            stdapi_registry_delete_value: [
              'client.sys.registry.delete_value'
            ],
            stdapi_registry_enum_key: [
              'client.sys.registry.enum_key'
            ],
            stdapi_registry_enum_key_direct: [
              'client.sys.registry.enum_key_direct'
            ],
            stdapi_registry_enum_value: [
              'client.sys.registry.enum_value'
            ],
            stdapi_registry_enum_value_direct: [
              'session.sys.registry.enum_value_direct'
            ],
            stdapi_registry_load_key: [
              'session.sys.registry.load_key'
            ],
            stdapi_registry_open_key: [
              'client.sys.registry.open_key'
            ],
            stdapi_registry_open_remote_key: [
              'session.sys.registry.open_remote_key'
            ],
            stdapi_registry_query_class: [
              'client.sys.registry.query_class'
            ],
            stdapi_registry_query_value: [
              'client.sys.registry.query_value'
            ],
            stdapi_registry_query_value_direct: [
              'client.sys.registry.query_value_direct'
            ],
            stdapi_registry_set_value: [
              'client.sys.registry.set_value'
            ],
            stdapi_registry_set_value_direct: [
              'session.sys.registry.set_value_direct'
            ],
            stdapi_registry_unload_key: [
              'client.sys.registry.unload_key'
            ],
            stdapi_sys_config_driver_list: [
              'session.sys.config.getdrivers'
            ],
            stdapi_sys_config_drop_token: [
              'client.sys.config.drop_token'
            ],
            stdapi_sys_config_getenv: [
              'session.sys.config.getenv',
              'client.sys.config.getenvs',
            ],
            stdapi_sys_config_getprivs: [
              'client.sys.config.getprivs'
            ],
            stdapi_sys_config_getsid: [
              'client.sys.config.is_system?',
              'session.sys.config.getsid'
            ],
            stdapi_sys_config_getuid: [
              'client.sys.config.getuid'
            ],
            stdapi_sys_config_localtime: [
              'client.sys.config.localtime'
            ],
            stdapi_sys_config_rev2self: [
              'session.sys.config.revert_to_self'
            ],
            stdapi_sys_config_steal_token: [
              'client.sys.config.steal_token'
            ],
            stdapi_sys_config_sysinfo: [
              'client.sys.config.sysinfo'
            ],
            "stdapi_sys_eventlog_*": [
              'session.sys.eventlog'
            ],
            stdapi_sys_eventlog_clear: [
            ],
            stdapi_sys_eventlog_close: [
            ],
            stdapi_sys_eventlog_numrecords: [
            ],
            stdapi_sys_eventlog_oldest: [
            ],
            stdapi_sys_eventlog_read: [
            ],
            stdapi_sys_power_exitwindows: [
              'client.sys.power.reboot'
            ],
            stdapi_sys_process_attach: [
              'client.sys.process.open'
            ],
            stdapi_sys_process_close: [
              'process.close'
            ],
            stdapi_sys_process_execute: [
              'client.sys.process.execute'
            ],
            stdapi_sys_process_get_info: [
              'client.sys.process.get_info'
            ],
            stdapi_sys_process_get_processes: [
              'client.sys.process.get_processes',
              'session.sys.process.each_process'
            ],
            stdapi_sys_process_getpid: [
              'client.sys.process.getpid'
            ],
            stdapi_sys_process_image_get_images: [
              'client.sys.process.image.get_images',
              'client.sys.process.image.each_image'
            ],
            stdapi_sys_process_image_get_proc_address: [
              'client.sys.process.image.get_procedure_address'
            ],
            stdapi_sys_process_image_load: [
              'client.sys.process.image.load'
            ],
            stdapi_sys_process_image_unload: [
              'client.sys.process.image.unload'
            ],
            stdapi_sys_process_kill: [
              'client.sys.process.kill',
              'process.kill'
            ],
            stdapi_sys_process_memory_allocate: [
              'process.memory.allocate'
            ],
            stdapi_sys_process_memory_free: [
              'process.memory.free'
            ],
            stdapi_sys_process_memory_lock: [
              'client.sys.process.memory.lock'
            ],
            stdapi_sys_process_memory_protect: [
              'process.memory.protect'
            ],
            stdapi_sys_process_memory_query: [
              'process.memory.query'
            ],
            stdapi_sys_process_memory_read: [
              'process.memory.read'
            ],
            stdapi_sys_process_memory_unlock: [
              'client.sys.process.memory.unlock'
            ],
            stdapi_sys_process_memory_write: [
              'process.memory.write'
            ],
            stdapi_sys_process_thread_close: [
              'client.sys.process.thread.close'
            ],
            stdapi_sys_process_thread_create: [
              'client.sys.process.thread.create',
              'process.thread.create'
            ],
            stdapi_sys_process_thread_get_threads: [
              'process.threads.get_threads',
              'process.threads.each_thread'
            ],
            stdapi_sys_process_thread_open: [
              'process.thread.open'
            ],
            stdapi_sys_process_thread_query_regs: [
              'process.thread.query_regs'
            ],
            stdapi_sys_process_thread_resume: [
              'process.thread.open.resume'
            ],
            stdapi_sys_process_thread_set_regs: [
              'client.sys.process.thread.set_regs'
            ],
            stdapi_sys_process_thread_suspend: [
              'process.thread.open.suspend'
            ],
            stdapi_sys_process_thread_terminate: [
              'process.thread.open.terminate'
            ],
            stdapi_sys_process_wait: [
              'client.sys.thread.process.wait'
            ],
            stdapi_ui_desktop_enum: [
              'client.ui.enum_desktops'
            ],
            stdapi_ui_desktop_get: [
              'client.ui.get_desktop'
            ],
            stdapi_ui_desktop_screenshot: [
              'session.ui.screenshot'
            ],
            stdapi_ui_desktop_set: [
              'client.ui.set_desktop'
            ],
            stdapi_ui_enable_keyboard: [
              'client.ui.enable_keyboard'
            ],
            stdapi_ui_enable_mouse: [
              'client.ui.enable_mouse'
            ],
            stdapi_ui_get_idle_time: [
              'session.ui.idle_time'
            ],
            stdapi_ui_get_keys_utf8: [
              'session.ui.keyscan_dump'
            ],
            stdapi_ui_send_keyevent: [
              'session.ui.keyevent_send'
            ],
            stdapi_ui_send_keys: [
              'client.ui.keyboard_send'
            ],
            stdapi_ui_send_mouse: [
              'client.ui.mouse'
            ],
            stdapi_ui_start_keyscan: [
              'client.ui.keyscan_start'
            ],
            stdapi_ui_stop_keyscan: [
              'client.ui.keyscan_stop'
            ],
            stdapi_ui_unlock_desktop: [
              'client.ui.unlock_desktop'
            ],
            "stdapi_webcam_*": [
              'session.webcam'
            ],
            stdapi_audio_mic_start: [
              'client.mic.mic_start'
            ],
            stdapi_audio_mic_stop: [
              'client.mic.mic_stop'
            ],
            stdapi_audio_mic_list: [
              'client.mic.mic_list'
            ]
          }

          priv_command_ids = {
            priv_elevate_getsystem: [
              'session.priv.getsystem',
            ],
            priv_fs_blank_directory_mace: [
              'client.priv.fs.blank_directory_mace',
            ],
            priv_fs_blank_file_mace: [
              'client.priv.fs.blank_file_mace'
            ],
            priv_fs_get_file_mace: [
              'client.priv.fs.get_file_mace'
            ],
            priv_fs_set_file_mace: [
              'session.priv.fs.set_file_mace'
            ],
            priv_fs_set_file_mace_from_file: [
              'session.priv.fs.set_file_mace_from_file'
            ],
            priv_passwd_get_sam_hashes: [
              'client.priv.sam_hashes'
            ]
          }

          extapi_command_ids = {
            extapi_adsi_domain_query: [
              'session.extapi.adsi.domain_query'
            ],
            extapi_clipboard_get_data: [
              'session.extapi.clipboard.get_data',
            ],
            extapi_clipboard_monitor_dump: [
              'client.extapi.clipboard.monitor_dump',
            ],
            extapi_clipboard_monitor_pause: [
              'client.extapi.clipboard.monitor_pause',
            ],
            extapi_clipboard_monitor_purge: [
              'client.extapi.clipboard.monitor_purge',
            ],
            extapi_clipboard_monitor_resume: [
              'client.extapi.clipboard.monitor_resume',
            ],
            extapi_clipboard_monitor_start: [
              'client.extapi.clipboard.monitor_start'
            ],
            extapi_clipboard_monitor_stop: [
              'client.extapi.clipboard.monitor_stop'
            ],
            extapi_clipboard_set_data: [
              'session.extapi.clipboard.set_text',
            ],
            extapi_ntds_parse: [
              'client.extapi.ntds.parse',
              NodePattern.new('(send (const (const (const (const nil? :Metasploit) :Framework) :NTDS) :Parser) :new _*)')
            ],
            extapi_pageant_send_query: [
              'session.extapi.pageant.forward',
            ],
            extapi_service_control: [
              'client.extapi.service.control',
            ],
            extapi_service_enum: [
              'session.extapi.service.enumerate',
            ],
            extapi_service_query: [
              'session.extapi.service.query',
            ],
            extapi_window_enum: [
              'client.extapi.window.enumerate',
            ],
            extapi_wmi_query: [
              'session.extapi.wmi.query',
            ]
          }

          android_command_ids = {
            'android_*': [
              'client.android'
            ],
            android_activity_start: [
            ],
            android_check_root: [
            ],
            android_device_shutdown: [
            ],
            android_dump_calllog: [
            ],
            android_dump_contacts: [
            ],
            android_dump_sms: [
            ],
            android_geolocate: [
            ],
            android_hide_app_icon: [
            ],
            android_interval_collect: [
            ],
            android_send_sms: [
            ],
            android_set_audio_mode: [
            ],
            android_set_wallpaper: [
            ],
            android_sqlite_query: [
            ],
            android_wakelock: [
            ],
            android_wlan_geolocate: [
            ]
          }

          kiwi_command_ids = {
            kiwi_exec_cmd: [
              'session.kiwi',
            ]
          }

          appapi_app_install_command_ids = {
            appapi_app_install: [
              'client.appapi.app_install'
            ],
            appapi_app_list: [
              'client.appapi.app_list'
            ],
            appapi_app_run: [
              'client.appapi.app_run'
            ],
            appapi_app_uninstall: [
              'client.appapi.app_uninstall'
            ]
          }

          espia_command_ids = {
            espia_image_get_dev_screen: [
              'client.espia.espia_image_get_dev_screen'
            ]
          }

          incognito_command_ids = {
            incognito_add_group_user: [
              'session.incognito.incognito_add_group_user'
            ],
            incognito_add_localgroup_user: [
              'session.incognito.incognito_add_localgroup_user'
            ],
            incognito_add_user: [
              'session.incognito.incognito_add_user'
            ],
            incognito_impersonate_token: [
              'session.incognito.incognito_impersonate_token'
            ],
            incognito_list_tokens: [
              'session.incognito.incognito_list_tokens'
            ],
            incognito_snarf_hashes: [
              'session.incognito.incognito_snarf_hashes'
            ]
          }

          powershell_command_ids = {
            powershell_assembly_load: [
              'client.powershell.import_file'
            ],
            powershell_execute: [
              'session.powershell.execute_string'
            ],
            powershell_session_remove: [
              'client.powershell.session_remove'
            ],
            powershell_shell: [
              'client.powershell.shell'
            ]
          }

          lanattacks_command_ids = {
            lanattacks_add_tftp_file: [
              'session.lanattacks.tftp.add_file'
            ],
            lanattacks_dhcp_log: [
              'session.lanattacks.dhcp.log'
            ],
            lanattacks_reset_dhcp: [
              'client.lanattacks.dhcp.reset'
            ],
            lanattacks_reset_tftp: [
              'client.lanattacks.tftp.reset'
            ],
            lanattacks_set_dhcp_option: [
              'client.lanattacks.dhcp.set_option',
              'client.lanattacks.dhcp.load_options'
            ],
            lanattacks_start_dhcp: [
              'client.lanattacks.dhcp.start'
            ],
            lanattacks_start_tftp: [
              'client.lanattacks.tftp.start'
            ],
            lanattacks_stop_dhcp: [
              'client.lanattacks.dhcp.stop'
            ],
            lanattacks_stop_tftp: [
              'client.lanattacks.tftp.stop'
            ]
          }

          peinjector_command_ids = {
            peinjector_inject_shellcode: [
              'client.peinjector.inject_shellcode'
            ]
          }

          python_command_ids = {
            python_execute: [
              'client.python.execute_string',
              'client.python.import'
            ],
            python_reset: [
              'client.python.reset'
            ]
          }

          unhook_pe_command_ids = {
            unhook_pe: [
              'client.unhook.unhook_pe'
            ]
          }

          sniffer_command_ids = {
            sniffer_capture_dump: [
              'client.sniffer.capture_dump'
            ],
            sniffer_capture_dump_read: [
              'client.sniffer.capture_dump_read'
            ],
            sniffer_capture_release: [
              'client.sniffer.capture_release'
            ],
            sniffer_capture_start: [
              'client.sniffer.capture_start'
            ],
            sniffer_capture_stats: [
              'client.sniffer.capture_start'
            ],
            sniffer_capture_stop: [
              'client.sniffer.capture_stop'
            ],
            sniffer_interfaces: [
              'client.sniffer.interfaces'
            ]
          }

          winpmem_dump_ram_command_ids = {
            winpmem_dump_ram: [
              'client.winpmem.dump_ram'
            ]
          }

          command_ids_to_expressions = {
            **core_channel_ids,
            **stdapi_command_ids,
            **priv_command_ids,
            **extapi_command_ids,
            **android_command_ids,
            **kiwi_command_ids,
            **appapi_app_install_command_ids,
            **espia_command_ids,
            **incognito_command_ids,
            **powershell_command_ids,
            **lanattacks_command_ids,
            **peinjector_command_ids,
            **python_command_ids,
            **sniffer_command_ids,
            **unhook_pe_command_ids,
            **winpmem_dump_ram_command_ids
          }

          command_ids_to_expressions_mappings = command_ids_to_expressions.flat_map do |command_id, matchers|
            matchers.map do |value|
              {
                matcher: value.is_a?(NodePattern) ? value : node_pattern_for(value),
                commands: [command_id.to_s]
              }
            end
          end

          expressions_to_commands_ids_mappings = expressions_to_commands.map do |matcher, command_ids|
            {
              matcher: node_pattern_for(matcher.to_s),
              commands: command_ids
            }
          end

          @mappings = command_ids_to_expressions_mappings + expressions_to_commands_ids_mappings
        end

        def on_send(node)
          mappings.each do |mapping|
            matcher = mapping[:matcher]
            commands = mapping[:commands]
            next unless matcher.match(node)

            commands.each do |command|
              unless @current_frame.identified_commands.include?(command)
                @current_frame.identified_commands << command
              end
            end

            # Add an offense, but don't provide an autocorrect.
            # There will be a final autocorrect to fix all issues
            commands.each do |command|
              unless @current_frame.current_commands.include?(command)
                add_offense(node)
              end
            end

            break
          end
        end

        def autocorrector
          lambda do |corrector|
            # Removes the railgun_api call if we are already calling railgun in its entirety.
            if @current_frame.identified_commands.include?("stdapi_railgun_*") && @current_frame.identified_commands.include?("stdapi_railgun_api*")
              @current_frame.identified_commands -= ["stdapi_railgun_api*"]
            end

            # Handles modules that no longer have api calls with the code but have a commands list present
            if @current_frame.identified_commands.empty? && !@current_frame.current_commands.empty?
              # White spacing handling based of node offsets
              commands_whitespace = offset(nodes[:commands_node])
              array_content_whitespace = commands_whitespace + '  '

              # Formatting to add missing commands node when the method has a compat node & meterpreter node present
              new_hash = "'Commands' => %w[\n"
              new_hash <<= "#{array_content_whitespace}#{@current_frame.identified_commands.join("\n#{array_content_whitespace}")}\n" unless @current_frame.identified_commands.empty?
              new_hash <<= "#{commands_whitespace}]"

              corrector.replace(nodes[:commands_node], new_hash)

              # Handles scenario where we have both compat & meterpreter hashes
              # but no commands array present within a module
            elsif nodes[:compat_node] && nodes[:meterpreter_node] && nodes[:commands_node].nil?
              meterpreter_hash_node = nodes[:meterpreter_node].children[1]

              # White spacing handling based of node offsets
              meterpreter_whitespace = offset(nodes[:meterpreter_node])
              commands_whitespace = meterpreter_whitespace + '  '
              array_content_whitespace = commands_whitespace + '  '

              # Formatting to add missing commands node when the method has a compat node & meterpreter node present
              new_hash =
                "{\n" \
                "#{commands_whitespace}'Commands' => %w[" \
                "\n#{array_content_whitespace}#{@current_frame.identified_commands.join("\n#{array_content_whitespace}")}\n" \
                "#{commands_whitespace}]\n" \
                "#{meterpreter_whitespace}}"

              corrector.replace(meterpreter_hash_node, new_hash)

              # Handles scenario when we have a compat hash, but no meterpreter hash
              # and compats array present within a module
            elsif nodes[:compat_node] && nodes[:meterpreter_node].nil? && nodes[:commands_node].nil?
              # White spacing handling based of node offsets
              compat_whitespace = offset(nodes[:compat_node])
              meterpreter_whitespace = compat_whitespace + '  '
              commands_whitespace = meterpreter_whitespace + '  '
              array_content_whitespace = commands_whitespace + '  '

              # Formatting to add missing commands node when the method has a compat node & meterpreter node present
              new_hash =
                "\n" \
                "#{meterpreter_whitespace}'Meterpreter' => {\n" \
                "#{commands_whitespace}'Commands' => %w[" \
                "\n#{array_content_whitespace}#{@current_frame.identified_commands.join("\n#{array_content_whitespace}")}\n" \
                "#{commands_whitespace}]\n" \
                "#{meterpreter_whitespace}}" \

              if !nodes[:compat_node].value.children.last.nil?
                new_hash_if_compat_has_value = ','
                new_hash_if_compat_has_value << new_hash
                corrector.insert_after(nodes[:compat_node].value.children.last, new_hash_if_compat_has_value)
              else
                alt_new_hash = '{'
                alt_new_hash << new_hash
                alt_new_hash << "\n#{compat_whitespace}}"
                corrector.replace(nodes[:compat_node].value, alt_new_hash)
              end

            elsif !nodes[:initialize_node].nil? && !nodes[:super_node].nil? && nodes[:info_node].nil?
              super_whitespace = offset(nodes[:super_node])
              compat_whitespace = super_whitespace + '  '
              meterpreter_whitespace = compat_whitespace + '  '
              commands_whitespace = meterpreter_whitespace + '  '
              array_content_whitespace = commands_whitespace + '  '

              # Formatting to add missing commands node when the method has a compat node & meterpreter node present
              new_hash =
                "\n#{compat_whitespace}'Compat' => {\n" \
                "#{meterpreter_whitespace}'Meterpreter' => {\n" \
                "#{commands_whitespace}'Commands' => %w[" \
                "\n#{array_content_whitespace}#{@current_frame.identified_commands.join("\n#{array_content_whitespace}")}\n" \
                "#{commands_whitespace}]\n" \
                "#{meterpreter_whitespace}}\n" \
                "#{compat_whitespace}}"

              corrector.insert_after(nodes[:super_node].children.first, new_hash)

              # Handles scenario when we have no compats hash, no meterpreter hash
              # and  no compats array present within the module, but we do have an initialize method present
            elsif nodes[:compat_node].nil? && nodes[:meterpreter_node].nil? && nodes[:commands_node].nil? && !nodes[:initialize_node].nil?
              # White spacing handling based of node offsets
              compat_whitespace = offset(nodes[:info_node])
              meterpreter_whitespace = compat_whitespace + '  '
              commands_whitespace = meterpreter_whitespace + '  '
              array_content_whitespace = commands_whitespace + '  '

              # Formatting to add missing commands node when the method has a compat node & meterpreter node present
              new_hash =
                ",\n#{compat_whitespace}'Compat' => {\n" \
                "#{meterpreter_whitespace}'Meterpreter' => {\n" \
                "#{commands_whitespace}'Commands' => %w[" \
                "\n#{array_content_whitespace}#{@current_frame.identified_commands.join("\n#{array_content_whitespace}")}\n" \
                "#{commands_whitespace}]\n" \
                "#{meterpreter_whitespace}}\n" \
                "#{compat_whitespace}}"

              corrector.insert_after(nodes[:info_node].children.last, new_hash)

              # Handles scenario when we have no compats hash, no meterpreter hash
              # and  no compats array present no initialize method present within the module
            elsif nodes[:compat_node].nil? && nodes[:meterpreter_node].nil? && nodes[:commands_node].nil? && nodes[:initialize_node].nil?
              # White spacing handling based of node offset
              body = nodes[:investigated_node].body
              def_whitespace = offset(body)
              super_whitespace = def_whitespace + '  '
              update_info_whitespace = super_whitespace + '  '
              info_whitespace = update_info_whitespace + '  '
              meterpreter_whitespace = info_whitespace + '  '
              commands_whitespace = meterpreter_whitespace + '  '
              array_content_whitespace = commands_whitespace + '  '

              # Formatting to add missing commands node when the method has a compat node & meterpreter node present
              new_hash =
                'def initialize(info = {})' \
                "\n#{super_whitespace}super(" \
                "\n#{update_info_whitespace}update_info(" \
                "\n#{info_whitespace}info," \
                "\n#{info_whitespace}'Compat' => {" \
                "\n#{meterpreter_whitespace}'Meterpreter' => {" \
                "\n#{commands_whitespace}'Commands' => %w[" \
                "\n#{array_content_whitespace}#{@current_frame.identified_commands.join("\n#{array_content_whitespace}")}" \
                "\n#{commands_whitespace}]" \
                "\n#{meterpreter_whitespace}}" \
                "\n#{info_whitespace}}" \
                "\n#{update_info_whitespace})" \
                "\n#{super_whitespace})" \
                "\n#{def_whitespace}end\n\n" \
                "#{def_whitespace}"

              corrector.insert_before(body, new_hash)

            else
              array_node = nodes[:commands_node].children[1]
              commands_whitespace = offset(nodes[:commands_node])
              array_whitespace = commands_whitespace + '  '

              new_array = "%w[\n#{array_whitespace}#{@current_frame.identified_commands.join("\n#{array_whitespace}")}\n#{commands_whitespace}]"
              corrector.replace(array_node, new_array)
            end
          end
        end
      end
    end
  end
end
