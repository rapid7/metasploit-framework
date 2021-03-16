# -*- coding: binary -*-
module Rex
module Proto
module SMB

class SimpleClient

require 'rex/text'
require 'rex/struct2'
require 'ruby_smb'

# Some short-hand class aliases
CONST = Rex::Proto::SMB::Constants
CRYPT = Rex::Proto::SMB::Crypt
UTILS = Rex::Proto::SMB::Utils
XCEPT = Rex::Proto::SMB::Exceptions
EVADE = Rex::Proto::SMB::Evasions

# Public accessors
attr_accessor :last_error, :server_max_buffer_size

# Private accessors
attr_accessor :socket, :client, :direct, :shares, :last_share, :versions

  # Pass the socket object and a boolean indicating whether the socket is netbios or cifs
  def initialize(socket, direct = false, versions = [1, 2, 3], always_encrypt: true, backend: nil)
    self.socket = socket
    self.direct = direct
    self.versions = versions
    self.shares = {}
    self.server_max_buffer_size = 1024 # 4356 (workstation) or 16644 (server) expected

    if (self.versions == [1] && backend.nil?) || backend == :rex
      self.client = Rex::Proto::SMB::Client.new(socket)
    elsif (backend.nil? || backend == :ruby_smb)
      self.client = RubySMB::Client.new(RubySMB::Dispatcher::Socket.new(self.socket, read_timeout: 60),
                                        username: '',
                                        password: '',
                                        smb1: self.versions.include?(1),
                                        smb2: self.versions.include?(2),
                                        smb3: self.versions.include?(3),
                                        always_encrypt: always_encrypt
                    )
      self.client.evasion_opts = {
        # Padding is performed between packet headers and data
        'pad_data' => EVADE::EVASION_NONE,
        # File path padding is performed on all open/create calls
        'pad_file' => EVADE::EVASION_NONE,
        # Modify the \PIPE\ string in trans_named_pipe calls
        'obscure_trans_pipe' => EVADE::EVASION_NONE,
      }
    end
  end

  def login(name = '', user = '', pass = '', domain = '',
      verify_signature = false, usentlmv2 = false, usentlm2_session = true,
      send_lm = true, use_lanman_key = false, send_ntlm = true,
      native_os = 'Windows 2000 2195', native_lm = 'Windows 2000 5.0', spnopt = {})

    begin

      if (self.direct != true)
        self.client.session_request(name)
      end
      self.client.native_os = native_os
      self.client.native_lm = native_lm
      self.client.verify_signature = verify_signature
      self.client.use_ntlmv2 = usentlmv2
      self.client.usentlm2_session = usentlm2_session
      self.client.send_lm = send_lm
      self.client.use_lanman_key =  use_lanman_key
      self.client.send_ntlm = send_ntlm

      dlog("SMB version(s) to negotiate: #{self.versions}")
      ok = self.client.negotiate
      dlog("Negotiated SMB version: SMB#{negotiated_smb_version}")

      if self.client.is_a?(RubySMB::Client)
        self.server_max_buffer_size = self.client.server_max_buffer_size
      else
        self.server_max_buffer_size = ok['Payload'].v['MaxBuff']
      end

      # Disable NTLMv2 Session for Windows 2000 (breaks authentication on some systems)
      # XXX: This in turn breaks SMB auth for Windows 2000 configured to enforce NTLMv2
      # XXX: Tracked by ticket #4785#4785
      if self.client.native_lm =~ /Windows 2000 5\.0/ and usentlm2_session
      #	self.client.usentlm2_session = false
      end

      self.client.spnopt = spnopt

      # In case the user unsets the password option, we make sure this is
      # always a string
      pass ||= ''

      res = self.client.session_setup(user, pass, domain)
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      n = XCEPT::LoginError.new
      n.source = e
      if(e.respond_to?('error_code'))
        n.error_code   = e.error_code
        n.error_reason = e.get_error(e.error_code)
      end
      raise n
    end

    # RubySMB does not raise any exception if the Session Setup fails
    if self.client.is_a?(RubySMB::Client) && res != WindowsError::NTStatus::STATUS_SUCCESS
      n = XCEPT::LoginError.new
      n.source       = res
      n.error_code   = res.value
      n.error_reason = res.name
      raise n
    end

    return true
  end


  def login_split_start_ntlm1(name = '')

    begin

      if (self.direct != true)
        self.client.session_request(name)
      end

      # Disable extended security
      self.client.negotiate(false)
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      n = XCEPT::LoginError.new
      n.source = e
      if(e.respond_to?('error_code'))
        n.error_code   = e.error_code
        n.error_reason = e.get_error(e.error_code)
      end
      raise n
    end

    return true
  end


  def login_split_next_ntlm1(user, domain, hash_lm, hash_nt)
    begin
      ok = self.client.session_setup_no_ntlmssp_prehash(user, domain, hash_lm, hash_nt)
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      n = XCEPT::LoginError.new
      n.source = e
      if(e.respond_to?('error_code'))
        n.error_code   = e.error_code
        n.error_reason = e.get_error(e.error_code)
      end
      raise n
    end

    return true
  end

  def connect(share)
    ok = self.client.tree_connect(share)

    if self.client.is_a?(RubySMB::Client)
      tree_id = ok.id
    else
      tree_id = ok['Payload']['SMB'].v['TreeID']
    end

    self.shares[share] = tree_id
    self.last_share = share
  end

  def disconnect(share)
    if self.shares[share]
      ok = self.client.tree_disconnect(self.shares[share])
      self.shares.delete(share)
      return ok
    end
    false
  end

  def open(path, perm, chunk_size = 48000, read: true, write: false)
    if self.client.is_a?(RubySMB::Client)
      mode = 0
      if perm.include?('c')
        if perm.include?('o')
          mode = RubySMB::Dispositions::FILE_OPEN_IF
        elsif perm.include?('t')
          mode = RubySMB::Dispositions::FILE_OVERWRITE_IF
        else
          mode = RubySMB::Dispositions::FILE_CREATE
        end
      else
        if perm.include?('o')
          mode = RubySMB::Dispositions::FILE_OPEN
        elsif perm.include?('t')
          mode = RubySMB::Dispositions::FILE_OVERWRITE
        end
      end

      file_id = self.client.open(path, mode, read: true, write: write || perm.include?('w'))
    else
      mode = UTILS.open_mode_to_mode(perm)
      access = UTILS.open_mode_to_access(perm)

      ok = self.client.open(path, mode, access)
      file_id = ok['Payload'].v['FileID']
    end

    fh = OpenFile.new(self.client, path, self.client.last_tree_id, file_id, self.versions)
    fh.chunk_size = chunk_size
    fh
  end

  def delete(*args)
    if self.client.is_a?(RubySMB::Client)
      self.client.delete(args[0])
    else
      self.client.delete(*args)
    end
  end

  def create_pipe(path, perm = 'o')
    disposition = UTILS.create_mode_to_disposition(perm)
    ok = self.client.create_pipe(path, disposition)

    if self.client.is_a?(RubySMB::Client)
      file_id = ok
    else
      file_id = ok['Payload'].v['FileID']
    end

    fh = OpenPipe.new(self.client, path, self.client.last_tree_id, file_id, self.versions)
  end

  def trans_pipe(fid, data, no_response = nil)
    client.trans_named_pipe(fid, data, no_response)
  end

  def negotiated_smb_version
    return 1 if self.client.is_a?(Rex::Proto::SMB::Client)
    self.client.negotiated_smb_version || -1
  end

end
end
end
end

