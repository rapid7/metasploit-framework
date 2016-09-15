# -*- coding: binary -*-

require 'msf/base'
require 'msf/base/sessions/scriptable'
require 'rex/post/meterpreter'

module Msf
module Sessions

###
#
# This class represents a session compatible interface to a meterpreter server
# instance running on a remote machine.  It provides the means of interacting
# with the server instance both at an API level as well as at a console level.
#
###
class Meterpreter < Rex::Post::Meterpreter::Client

  include Msf::Session
  #
  # The meterpreter session is interactive
  #
  include Msf::Session::Interactive
  include Msf::Session::Comm

  #
  # This interface supports interacting with a single command shell.
  #
  include Msf::Session::Provider::SingleCommandShell

  include Msf::Session::Scriptable

  # Override for server implementations that can't do SSL
  def supports_ssl?
    true
  end

  # Override for server implementations that can't do zlib
  def supports_zlib?
    true
  end

  #
  # Initializes a meterpreter session instance using the supplied rstream
  # that is to be used as the client's connection to the server.
  #
  def initialize(rstream, opts={})
    super

    opts[:capabilities] = {
      :ssl => supports_ssl?,
      :zlib => supports_zlib?
    }

    # The caller didn't request to skip ssl, so make sure we support it
    if not opts[:skip_ssl]
      opts.merge!(:skip_ssl => (not supports_ssl?))
    end

    #
    # Parse options passed in via the datastore
    #

    # Extract the HandlerSSLCert option if specified by the user
    if opts[:datastore] and opts[:datastore]['HandlerSSLCert']
      opts[:ssl_cert] = opts[:datastore]['HandlerSSLCert']
    end

    # Don't pass the datastore into the init_meterpreter method
    opts.delete(:datastore)

    # Assume by default that 10 threads is a safe number for this session
    self.max_threads ||= 10

    #
    # Initialize the meterpreter client
    #
    self.init_meterpreter(rstream, opts)

    #
    # Create the console instance
    #
    self.console = Rex::Post::Meterpreter::Ui::Console.new(self)
  end

  #
  # Returns the session type as being 'meterpreter'.
  #
  def self.type
    "meterpreter"
  end

  #
  # Calls the class method
  #
  def type
    self.class.type
  end

  ##
  # :category: Msf::Session::Provider::SingleCommandShell implementors
  #
  # Create a channelized shell process on the target
  #
  def shell_init
    return true if @shell

    # COMSPEC is special-cased on all meterpreters to return a viable
    # shell.
    sh = fs.file.expand_path("%COMSPEC%")
    @shell = sys.process.execute(sh, nil, { "Hidden" => true, "Channelized" => true })

  end

  ##
  # :category: Msf::Session::Provider::SingleCommandShell implementors
  #
  # Read from the command shell.
  #
  def shell_read(length=nil, timeout=1)
    shell_init

    length = nil if length.nil? or length < 0
    begin
      rv = nil
      # Meterpreter doesn't offer a way to timeout on the victim side, so
      # we have to do it here.  I'm concerned that this will cause loss
      # of data.
      Timeout.timeout(timeout) {
        rv = @shell.channel.read(length)
      }
      framework.events.on_session_output(self, rv) if rv
      return rv
    rescue ::Timeout::Error
      return nil
    rescue ::Exception => e
      shell_close
      raise e
    end
  end

  ##
  # :category: Msf::Session::Provider::SingleCommandShell implementors
  #
  # Write to the command shell.
  #
  def shell_write(buf)
    shell_init

    begin
      framework.events.on_session_command(self, buf.strip)
      len = @shell.channel.write("#{buf}\n")
    rescue ::Exception => e
      shell_close
      raise e
    end

    len
  end

  ##
  # :category: Msf::Session::Provider::SingleCommandShell implementors
  #
  # Terminate the shell channel
  #
  def shell_close
    @shell.close
    @shell = nil
  end

  def shell_command(cmd)
    # Send the shell channel's stdin.
    shell_write(cmd + "\n")

    timeout = 5
    etime = ::Time.now.to_f + timeout
    buff = ""

    # Keep reading data until no more data is available or the timeout is
    # reached.
    while (::Time.now.to_f < etime)
      res = shell_read(-1, timeout)
      break unless res
      timeout = etime - ::Time.now.to_f
      buff << res
    end

    buff
  end

  #
  # Called by PacketDispatcher to resolve error codes to names.
  # This is the default version (return the number itself)
  #
  def lookup_error(code)
    "#{code}"
  end

  ##
  # :category: Msf::Session overrides
  #
  # Cleans up the meterpreter client session.
  #
  def cleanup
    cleanup_meterpreter

    super
  end

  ##
  # :category: Msf::Session overrides
  #
  # Returns the session description.
  #
  def desc
    "Meterpreter"
  end


  ##
  # :category: Msf::Session::Scriptable implementors
  #
  # Runs the meterpreter script in the context of a script container
  #
  def execute_file(full_path, args)
    o = Rex::Script::Meterpreter.new(self, full_path)
    o.run(args)
  end


  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Initializes the console's I/O handles.
  #
  def init_ui(input, output)
    self.user_input = input
    self.user_output = output
    console.init_ui(input, output)
    console.set_log_source(log_source)

    super
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Resets the console's I/O handles.
  #
  def reset_ui
    console.unset_log_source
    console.reset_ui
  end

  #
  # Terminates the session
  #
  def kill
    begin
      cleanup_meterpreter
      self.sock.close if self.sock
    rescue ::Exception
    end
    # deregister will actually trigger another cleanup
    framework.sessions.deregister(self)
  end

  #
  # Run the supplied command as if it came from suer input.
  #
  def queue_cmd(cmd)
    console.queue_cmd(cmd)
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Explicitly runs a command in the meterpreter console.
  #
  def run_cmd(cmd)
    console.run_single(cmd)
  end

  #
  # Load the stdapi extension.
  #
  def load_stdapi()
    original = console.disable_output
    console.disable_output = true
    console.run_single('load stdapi')
    console.disable_output = original
  end

  #
  # Load the priv extension.
  #
  def load_priv()
    original = console.disable_output

    console.disable_output = true
    console.run_single('load priv')
    console.disable_output = original
  end

  #
  # Validate session information by checking for a machine_id response
  #
  def is_valid_session?(timeout=10)
    return true if self.machine_id

    begin
      self.machine_id = self.core.machine_id(timeout)
      self.payload_uuid ||= self.core.uuid(timeout)

      return true
    rescue ::Rex::Post::Meterpreter::RequestError
      # This meterpreter doesn't support core_machine_id
      return true
    rescue ::Exception => e
      dlog("Session #{self.sid} did not respond to validation request #{e.class}: #{e}")
    end
    false
  end

  def update_session_info
    username = self.sys.config.getuid
    sysinfo  = self.sys.config.sysinfo
    tuple = self.platform.split('/')

    #
    # Windows meterpreter currently needs 'win32' or 'win64' to be in the
    # second half of the platform tuple, in order for various modules and
    # library code match on that specific string.
    #
    if self.platform !~ /win32|win64/

      platform = case self.sys.config.sysinfo['OS']
        when /windows/i
          Msf::Module::Platform::Windows
        when /darwin/i
          Msf::Module::Platform::OSX
        when /freebsd/i
          Msf::Module::Platform::FreeBSD
        when /netbsd/i
          Msf::Module::Platform::NetBSD
        when /openbsd/i
          Msf::Module::Platform::OpenBSD
        when /sunos/i
          Msf::Module::Platform::Solaris
        when /android/i
          Msf::Module::Platform::Android
        else
          Msf::Module::Platform::Linux
      end.realname.downcase

      #
      # This normalizes the platform from 'python/python' to 'python/linux'
      #
      self.platform = "#{tuple[0]}/#{platform}"
    end


    safe_info = "#{username} @ #{sysinfo['Computer']}"
    safe_info.force_encoding("ASCII-8BIT") if safe_info.respond_to?(:force_encoding)
    # Should probably be using Rex::Text.ascii_safe_hex but leave
    # this as is for now since "\xNN" is arguably uglier than "_"
    # showing up in various places in the UI.
    safe_info.gsub!(/[\x00-\x08\x0b\x0c\x0e-\x19\x7f-\xff]+/n,"_")
    self.info = safe_info
  end

  #
  # Populate the session information.
  #
  # Also reports a session_fingerprint note for host os normalization.
  #
  def load_session_info
    begin
      ::Timeout.timeout(60) do
        update_session_info

        hobj = nil

        nhost = find_internet_connected_address

        original_session_host = self.session_host
        # If we found a better IP address for this session, change it
        # up.  Only handle cases where the DB is not connected here
        if nhost && !(framework.db && framework.db.active)
          self.session_host = nhost
        end

        # The rest of this requires a database, so bail if it's not
        # there
        return if !(framework.db && framework.db.active)

        ::ActiveRecord::Base.connection_pool.with_connection {
          wspace = framework.db.find_workspace(workspace)

          # Account for finding ourselves on a different host
          if nhost and self.db_record
            # Create or switch to a new host in the database
            hobj = framework.db.report_host(:workspace => wspace, :host => nhost)
            if hobj
              self.session_host = nhost
              self.db_record.host_id = hobj[:id]
            end
          end

          framework.db.report_note({
            :type => "host.os.session_fingerprint",
            :host => self,
            :workspace => wspace,
            :data => {
              :name => sys.config.sysinfo["Computer"],
              :os => sys.config.sysinfo["OS"],
              :arch => sys.config.sysinfo["Architecture"],
            }
          })

          if self.db_record
            self.db_record.desc = safe_info
            self.db_record.save!
          end

          # XXX: This is obsolete given the Mdm::Host.normalize_os() support for host.os.session_fingerprint
          # framework.db.update_host_via_sysinfo(:host => self, :workspace => wspace, :info => sysinfo)

          if nhost
            framework.db.report_note({
              :type      => "host.nat.server",
              :host      => original_session_host,
              :workspace => wspace,
              :data      => { :info   => "This device is acting as a NAT gateway for #{nhost}", :client => nhost },
              :update    => :unique_data
            })
            framework.db.report_host(:host => original_session_host, :purpose => 'firewall' )

            framework.db.report_note({
              :type      => "host.nat.client",
              :host      => nhost,
              :workspace => wspace,
              :data      => { :info => "This device is traversing NAT gateway #{original_session_host}", :server => original_session_host },
              :update    => :unique_data
            })
            framework.db.report_host(:host => nhost, :purpose => 'client' )
          end
        }

      end
    rescue ::Interrupt
      dlog("Interrupt while loading sysinfo: #{e.class}: #{e}")
      raise $!
    rescue ::Exception => e
      # Log the error but otherwise ignore it so we don't kill the
      # session if reporting failed for some reason
      elog("Error loading sysinfo: #{e.class}: #{e}")
      dlog("Call stack:\n#{e.backtrace.join("\n")}")
    end
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Interacts with the meterpreter client at a user interface level.
  #
  def _interact
    framework.events.on_session_interact(self)
    # Call the console interaction subsystem of the meterpreter client and
    # pass it a block that returns whether or not we should still be
    # interacting.  This will allow the shell to abort if interaction is
    # canceled.
    console.interact { self.interacting != true }

    # If the stop flag has been set, then that means the user exited.  Raise
    # the EOFError so we can drop this handle like a bad habit.
    raise EOFError if (console.stopped? == true)
  end


  ##
  # :category: Msf::Session::Comm implementors
  #
  # Creates a connection based on the supplied parameters and returns it to
  # the caller.  The connection is created relative to the remote machine on
  # which the meterpreter server instance is running.
  #
  def create(param)
    sock = nil

    # Notify handlers before we create the socket
    notify_before_socket_create(self, param)

    sock = net.socket.create(param)

    # sf: unsure if we should raise an exception or just return nil. returning nil for now.
    #if( sock == nil )
    #  raise Rex::UnsupportedProtocol.new(param.proto), caller
    #end

    # Notify now that we've created the socket
    notify_socket_created(self, sock, param)

    # Return the socket to the caller
    sock
  end

  attr_accessor :platform
  attr_accessor :binary_suffix
  attr_accessor :console # :nodoc:
  attr_accessor :skip_ssl
  attr_accessor :skip_cleanup
  attr_accessor :target_id
  attr_accessor :max_threads

protected

  attr_accessor :rstream # :nodoc:

  # Rummage through this host's routes and interfaces looking for an
  # address that it uses to talk to the internet.
  #
  # @see Rex::Post::Meterpreter::Extensions::Stdapi::Net::Config#get_interfaces
  # @see Rex::Post::Meterpreter::Extensions::Stdapi::Net::Config#get_routes
  # @return [String] The address from which this host reaches the
  #   internet, as ASCII. e.g.: "192.168.100.156"
  # @return [nil] If there is an interface with an address that matches
  #   {#session_host}
  def find_internet_connected_address

    ifaces = self.net.config.get_interfaces().flatten rescue []
    routes = self.net.config.get_routes().flatten rescue []

    # Try to match our visible IP to a real interface
    found = !!(ifaces.find { |i| i.addrs.find { |a| a == session_host } })
    nhost = nil

    # If the host has no address that matches what we see, then one of
    # us is behind NAT so we have to look harder.
    if !found
      # Grab all routes to the internet
      default_routes = routes.select { |r| r.subnet == "0.0.0.0" || r.subnet == "::" }

      default_routes.each do |route|
        # Now try to find an interface whose network includes this
        # Route's gateway, which means it's the one the host uses to get
        # to the interweb.
        ifaces.each do |i|
          # Try all the addresses this interface has configured
          addr_and_mask = i.addrs.zip(i.netmasks).find do |addr, netmask|
            bits = Rex::Socket.net2bitmask( netmask )
            range = Rex::Socket::RangeWalker.new("#{addr}/#{bits}") rescue nil

            !!(range && range.valid? && range.include?(route.gateway))
          end
          if addr_and_mask
            nhost = addr_and_mask[0]
            break
          end
        end
        break if nhost
      end

      if !nhost
        # No internal address matches what we see externally and no
        # interface has a default route. Fall back to the first
        # non-loopback address
        non_loopback = ifaces.find { |i| i.ip != "127.0.0.1" && i.ip != "::1" }
        if non_loopback
          nhost = non_loopback.ip
        end
      end
    end

    nhost
  end

end

end
end

