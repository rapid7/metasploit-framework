# -*- coding: binary -*-
require 'rex/post/meterpreter'
require 'bindata'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Play audio on remote system
#
###
class Console::CommandDispatcher::Stdapi::AudioOutput
  Klass = Console::CommandDispatcher::Stdapi::AudioOutput

  include Console::CommandDispatcher

  #
  # List of supported commands.
  #
  def commands
    all = {
      'play' => 'play an audio file on target system, nothing written on disk'
    }
    reqs = {
      'play' => []
    }

    filter_commands(all, reqs)
  end

  #
  # Name for this dispatcher
  #
  def name
    'Stdapi: Audio Output'
  end

  def cmd_play(*args)
    if args.length == 0
      print_line('Please specify a path to an audio file')
      return
    end

    audio_path = args[0]

    print_status("Playing #{audio_path}...")
    client.audio_output.play_file(audio_path)
    print_status('Done')
  end

  def cmd_play_tabs(str, words)
    tab_complete_filenames(str, words)
  end
end

end
end
end
end
