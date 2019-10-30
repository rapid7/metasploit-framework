#
# $Id$
# $Revision$
#

module Msf

###
#
# This class hooks all session creation events and plays a sound
#
###

class Plugin::EventSounds < Msf::Plugin

  attr_accessor :theme, :base, :queue, :queue_thread
  attr_reader   :try_harder, :excellent, :got_a_shell, :exploit_worked, :wonderful

  include Msf::SessionEvent

  def play_sound(event)
    self.queue.push(event)
  end

  def on_session_open(session)
    sound = [
      excellent,
      got_a_shell,
      exploit_worked,
      wonderful
    ].sample
    play_sound(sound)
  end

  def on_session_close(session, reason='')
    # Cannot find an audio clip of muts saying something suitable for this.
  end

  def on_session_fail(reason='')
    play_sound(try_harder)
  end

  def on_plugin_load
  end

  def on_plugin_unload
  end

  def start_sound_queue
    self.queue_thread = Thread.new do
      begin
      while(true)
        while(event = self.queue.shift)
          path = ::File.join(self.base, self.theme, "#{event}.wav")
          if(::File.exist?(path))
            Rex::Compat.play_sound(path)
          else
            print_status("Warning: sound file not found: #{path}")
          end
        end
        select(nil, nil, nil, 0.25)
      end
      rescue ::Exception => e
        print_status("Sound plugin: fatal error #{e} #{e.backtrace}")
      end
    end
  end

  def stop_sound_queue
    self.queue_thread.kill if self.queue_thread
    self.queue_thread = nil
    self.queue = []
  end


  def init_sound_paths
    @try_harder     = 'try_harder'
    @excellent      = 'excellent'
    @got_a_shell    = 'got_a_shell'
    @exploit_worked = 'exploit_worked'
    @wonderful      = 'wonderful'
  end


  def initialize(framework, opts)
    super

    init_sound_paths

    self.queue = []
    self.theme = opts['theme'] || 'default'
    self.base  = File.join(Msf::Config.data_directory, "sounds")
    self.framework.events.add_session_subscriber(self)
    start_sound_queue

    self.on_plugin_load
  end

  def cleanup
    self.on_plugin_unload
    self.framework.events.remove_session_subscriber(self)
    stop_sound_queue
  end

  def name
    "sounds"
  end

  def desc
    "Automatically plays a sound when various framework events occur"
  end

end
end

