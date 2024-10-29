module Msf
module Util
module WindowsRegistry

  class RemoteRegistry
    # Constants
    ROOT_KEY        = 0x2c
    REG_NONE        = 0x00
    REG_SZ          = 0x01
    REG_EXPAND_SZ   = 0x02
    REG_BINARY      = 0x03
    REG_DWORD       = 0x04
    REG_MULTISZ     = 0x07
    REG_QWORD       = 0x0b

    def initialize(winreg, name: nil, inline: false)
      @winreg = winreg
      @inline = inline
      case name
      when :sam
        require_relative 'sam'
        extend Sam
      when :security
        require_relative 'security'
        extend Security
      else
        wlog("[Msf::Util::WindowsRegistry::RemoteRegistry] Unknown :name argument: #{name}") unless name.blank?
      end
    end

    def create_ace(sid)
      access_mask = RubySMB::Dcerpc::Winreg::Regsam.new({
        write_dac: 1,
        read_control: 1,
        key_enumerate_sub_keys: 1,
        key_query_value: 1
      })
      Rex::Proto::MsDtyp::MsDtypAce.new({
        header: {
          ace_type: Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_ALLOWED_ACE_TYPE,
          ace_flags: { container_inherit_ace: 1 }
        },
        body: {
          access_mask: Rex::Proto::MsDtyp::MsDtypAccessMask.read(access_mask.to_binary_s),
          sid: sid
        }
      })
    end

    def backup_file_path
      return @backup_file_path if @backup_file_path

      if ! File.directory?(Msf::Config.local_directory)
        FileUtils.mkdir_p(Msf::Config.local_directory)
      end
      remote_host = @winreg.tree.client.dns_host_name
      remote_host = @winreg.tree.client.dispatcher.tcp_socket.peerhost if remote_host.blank?
      path = File.join(Msf::Config.local_directory, "remote_registry_sd_backup_#{remote_host}_#{Time.now.strftime("%Y%m%d%H%M%S")}.#{Rex::Text.rand_text_alpha(6)}.yml")
      @backup_file_path = File.expand_path(path)
    end

    def save_to_file(key, security_descriptor, security_information, path = backup_file_path)
      sd_info = {
        'key' => key,
        'security_info' => security_information,
        'sd' => security_descriptor.b.bytes.map { |c| '%02x' % c.ord }.join
      }
      File.open(path, 'w') do |fd|
        fd.write(sd_info.to_yaml)
      end
    end

    def read_from_file(filepath)
      sd_info = YAML.safe_load_file(filepath)
      sd_info['security_info'] = sd_info['security_info'].to_i
      sd_info
    end

    def delete_backup_file(path = backup_file_path)
      File.delete(path) if File.file?(path)
    end

    def change_dacl(key, sid)
      security_information =
        RubySMB::Field::SecurityDescriptor::OWNER_SECURITY_INFORMATION |
        RubySMB::Field::SecurityDescriptor::GROUP_SECURITY_INFORMATION |
        RubySMB::Field::SecurityDescriptor::DACL_SECURITY_INFORMATION

      security_descriptor = @winreg.get_key_security_descriptor(key, security_information, bind: false)
      dlog("[Msf::Util::WindowsRegistry::RemoteRegistry] Security descriptor for #{key}: #{security_descriptor.b.bytes.map { |c| '%02x' % c.ord }.join}")
      save_to_file(key, security_descriptor, RubySMB::Field::SecurityDescriptor::DACL_SECURITY_INFORMATION)

      parsed_sd = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(security_descriptor)
      ace = create_ace(sid)
      parsed_sd.dacl.aces << ace
      parsed_sd.dacl.acl_count += 1
      parsed_sd.dacl.acl_size += ace.num_bytes
      dlog("[Msf::Util::WindowsRegistry::RemoteRegistry] New security descriptor for #{key}: #{parsed_sd.to_binary_s.b.bytes.map { |c| '%02x' % c.ord }.join}")

      @winreg.set_key_security_descriptor(key, parsed_sd.to_binary_s, RubySMB::Field::SecurityDescriptor::DACL_SECURITY_INFORMATION, bind: false)

      security_descriptor
    rescue RubySMB::Dcerpc::Error::WinregError => e
      elog("[Msf::Util::WindowsRegistry::RemoteRegistry] Error while changing DACL on key `#{key}`: #{e}")
    end

    def restore_dacl(key, security_descriptor)
      begin
        dlog("[Msf::Util::WindowsRegistry::RemoteRegistry] Restoring DACL on key `#{key}`")
        @winreg.set_key_security_descriptor(key, security_descriptor, RubySMB::Field::SecurityDescriptor::DACL_SECURITY_INFORMATION, bind: false)
      rescue StandardError => e
        elog(
          "[Msf::Util::WindowsRegistry::RemoteRegistry] Error while restoring DACL on key `#{key}`: #{e}\n"\
          "The original security descriptor has been saved in `#{backup_file_path}`. "\
          "The auxiliary module `admin/registry_security_descriptor` can be used to "\
          "restore the security descriptor from this file."
        )
        # Reset the `backup_file_path` instance variable to make sure a new
        # backup filename will be generated. This way, this backup file won't
        # be deleted the next time `#restore_dacl` is called.
        @backup_file_path = nil
        return
      end
      delete_backup_file
    end

    def enum_values(key)
      sd_backup = change_dacl(key, Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_ADMINS) if @inline
      @winreg.enum_registry_values(key, bind: false).map do |value|
        value.to_s.encode(::Encoding::ASCII_8BIT)
      end
    ensure
      restore_dacl(key, sd_backup) if @inline && sd_backup
    end

    def enum_key(key)
      sd_backup = change_dacl(key, Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_ADMINS) if @inline
      @winreg.enum_registry_key(key, bind: false).map do |key|
        key.to_s.encode(::Encoding::ASCII_8BIT)
      end
    ensure
      restore_dacl(key, sd_backup) if @inline && sd_backup
    end

    def get_value(key, value_name = nil)
      sd_backup = change_dacl(key, Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_ADMINS) if @inline
      root_key, sub_key = key.gsub(/\//, '\\').split('\\', 2)
      root_key_handle = @winreg.open_root_key(root_key)
      subkey_handle = @winreg.open_key(root_key_handle, sub_key)
      begin
        reg_value = @winreg.query_value(subkey_handle, value_name.nil? ? '' : value_name)
        [reg_value.type.to_i, reg_value.data.to_s.b]
      rescue RubySMB::Dcerpc::Error::WinregError
        nil
      end
    ensure
      @winreg.close_key(subkey_handle) if subkey_handle
      @winreg.close_key(root_key_handle) if root_key_handle
      restore_dacl(key, sd_backup) if @inline && sd_backup
    end

  end
end
end
end


