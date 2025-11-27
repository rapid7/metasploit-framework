# -*- coding: binary -*-

require 'English'

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

        DEFAULT_VERSIONS = [1, 2, 3].freeze

        # Public accessors
        attr_accessor :last_error, :server_max_buffer_size

        # Private accessors
        attr_accessor :socket, :client, :direct, :shares, :last_share, :versions, :msf_session

        attr_reader :address, :port

        # Pass the socket object and a boolean indicating whether the socket is netbios or cifs
        def initialize(socket, direct = false, versions = DEFAULT_VERSIONS, always_encrypt: true, backend: nil, client: nil, msf_session: nil)
          self.msf_session = msf_session
          session_lifetime do
            self.socket = socket
            self.direct = direct
            self.versions = versions
            self.shares = {}
            self.server_max_buffer_size = 1024 # 4356 (workstation) or 16644 (server) expected

            if !client.nil?
              self.client = client
            elsif (self.versions == [1] && backend.nil?) || backend == :rex
              self.client = Rex::Proto::SMB::Client.new(socket)
            elsif (backend.nil? || backend == :ruby_smb)
              self.client = RubySMB::Client.new(RubySMB::Dispatcher::Socket.new(self.socket, read_timeout: 60),
                                                username: '',
                                                password: '',
                                                smb1: self.versions.include?(1),
                                                smb2: self.versions.include?(2),
                                                smb3: self.versions.include?(3),
                                                always_encrypt: always_encrypt)

              self.client.evasion_opts = {
                # Padding is performed between packet headers and data
                'pad_data' => EVADE::EVASION_NONE,
                # File path padding is performed on all open/create calls
                'pad_file' => EVADE::EVASION_NONE,
                # Modify the \PIPE\ string in trans_named_pipe calls
                'obscure_trans_pipe' => EVADE::EVASION_NONE
              }
            end
            @address, @port = self.socket.peerinfo.split(':')
          end
        end

        def login(name = '', user = '', pass = '', domain = '',
                  verify_signature = false, usentlmv2 = false, usentlm2_session = true,
                  send_lm = true, use_lanman_key = false, send_ntlm = true,
                  native_os = 'Windows 2000 2195', native_lm = 'Windows 2000 5.0', spnopt = {})
          session_lifetime do
            begin
              if (direct != true)
                client.session_request(name)
              end
              client.native_os = native_os
              client.native_lm = native_lm
              client.verify_signature = verify_signature
              client.use_ntlmv2 = usentlmv2
              client.usentlm2_session = usentlm2_session
              client.send_lm = send_lm
              client.use_lanman_key = use_lanman_key
              client.send_ntlm = send_ntlm

              dlog("SMB version(s) to negotiate: #{versions}")
              ok = client.negotiate
              dlog("Negotiated SMB version: SMB#{negotiated_smb_version}")

              if client.is_a?(RubySMB::Client)
                self.server_max_buffer_size = client.server_max_buffer_size
              elsif ok && ok['Payload']
                self.server_max_buffer_size = ok['Payload'].v['MaxBuff']
              else
                raise XCEPT::LoginError, 'SMB negotiation failed'
              end

              # Disable NTLMv2 Session for Windows 2000 (breaks authentication on some systems)
              # XXX: This in turn breaks SMB auth for Windows 2000 configured to enforce NTLMv2
              # XXX: Tracked by ticket #4785#4785
              if client.native_lm =~ (/Windows 2000 5\.0/) && usentlm2_session
                #	self.client.usentlm2_session = false
              end

              client.spnopt = spnopt

              # In case the user unsets the username or password option, we make sure this is
              # always a string
              user ||= ''
              pass ||= ''

              res = client.session_setup(user, pass, domain)
            rescue ::Interrupt
              raise $ERROR_INFO
            rescue ::Exception => e
              elog(e)
              n = XCEPT::LoginError.new
              n.source = e
              if e.respond_to?('error_code') && e.respond_to?('get_error')
                n.error_code = e.error_code
                n.error_reason = e.get_error(e.error_code)
              end
              raise n
            end

            # RubySMB does not raise any exception if the Session Setup fails
            if client.is_a?(RubySMB::Client) && res != WindowsError::NTStatus::STATUS_SUCCESS
              n = XCEPT::LoginError.new
              n.source = res
              n.error_code = res.value
              n.error_reason = res.name
              raise n
            end

            return true
          end
        end

        def login_split_start_ntlm1(name = '')
          session_lifetime do
            begin
              if (direct != true)
                client.session_request(name)
              end

              # Disable extended security
              client.negotiate(false)
            rescue ::Interrupt
              raise $ERROR_INFO
            rescue ::Exception => e
              n = XCEPT::LoginError.new
              n.source = e
              if (e.respond_to?('error_code'))
                n.error_code = e.error_code
                n.error_reason = e.get_error(e.error_code)
              end
              raise n
            end

            return true
          end
        end

        def login_split_next_ntlm1(user, domain, hash_lm, hash_nt)
          session_lifetime do
            begin
              client.session_setup_no_ntlmssp_prehash(user, domain, hash_lm, hash_nt)
            rescue ::Interrupt
              raise $ERROR_INFO
            rescue ::Exception => e
              n = XCEPT::LoginError.new
              n.source = e
              if (e.respond_to?('error_code'))
                n.error_code = e.error_code
                n.error_reason = e.get_error(e.error_code)
              end
              raise n
            end

            return true
          end
        end

        def connect(share)
          session_lifetime do
            ok = client.tree_connect(share)

            if client.is_a?(RubySMB::Client)
              tree_id = ok.id
            else
              tree_id = ok['Payload']['SMB'].v['TreeID']
            end

            shares[share] = tree_id
            self.last_share = share
          end
        end

        def disconnect(share)
          session_lifetime do
            if shares[share]
              ok = client.tree_disconnect(shares[share])
              shares.delete(share)
              return ok
            end
            false
          end
        end

        def open(path, perm, chunk_size = 48000, read: true, write: false)
          session_lifetime do
            if client.is_a?(RubySMB::Client)
              mode = 0
              if perm.include?('c')
                if perm.include?('o')
                  mode = RubySMB::Dispositions::FILE_OPEN_IF
                elsif perm.include?('t')
                  mode = RubySMB::Dispositions::FILE_OVERWRITE_IF
                else
                  mode = RubySMB::Dispositions::FILE_CREATE
                end
              elsif perm.include?('o')
                mode = RubySMB::Dispositions::FILE_OPEN
              elsif perm.include?('t')
                mode = RubySMB::Dispositions::FILE_OVERWRITE
              end

              file_id = client.open(path, mode, read: true, write: write || perm.include?('w'))

            else
              mode = UTILS.open_mode_to_mode(perm)
              access = UTILS.open_mode_to_access(perm)

              ok = client.open(path, mode, access)
              file_id = ok['Payload'].v['FileID']
            end

            fh = OpenFile.new(client, path, client.last_tree_id, file_id, versions)
            fh.chunk_size = chunk_size
            fh
          end
        end

        def delete(*args)
          session_lifetime do
            if client.is_a?(RubySMB::Client)
              client.delete(args[0])
            else
              client.delete(*args)
            end
          end
        end

        def create_pipe(path, perm = 'o')
          session_lifetime do
            disposition = UTILS.create_mode_to_disposition(perm)
            ok = client.create_pipe(path, disposition)

            if client.is_a?(RubySMB::Client)
              file_id = ok
            else
              file_id = ok['Payload'].v['FileID']
            end

            OpenPipe.new(client, path, client.last_tree_id, file_id, versions)
          end
        end

        def trans_pipe(fid, data, no_response = nil)
          session_lifetime do
            client.trans_named_pipe(fid, data, no_response)
          end
        end

        def negotiated_smb_version
          return 1 if client.is_a?(Rex::Proto::SMB::Client)

          client.negotiated_smb_version || -1
        end

        alias peerhost address

        def peerport
          port.to_i
        end

        def peerinfo
          Rex::Socket.to_authority(peerhost, peerport)
        end

        def signing_required
          if client.is_a?(Rex::Proto::SMB::Client)
            client.peer_require_signing
          else
            client.signing_required
          end
        end

        private

        attr_writer :address, :port

        def session_lifetime
          yield
        rescue RubySMB::Error::CommunicationError, ::Rex::ConnectionError, Errno::ENOTCONN, Errno::ECONNRESET, Errno::ECONNREFUSED, Errno::ETIMEDOUT
          if msf_session
            msf_session.kill
          end
          raise
        end
      end
    end
  end
end
