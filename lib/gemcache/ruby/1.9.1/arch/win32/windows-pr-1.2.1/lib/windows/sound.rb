require 'windows/api'

module Windows  
  module Sound
    API.auto_namespace = 'Windows::Sound'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = false

    private

    SND_SYNC          = 0x0000  # play synchronously (default)
    SND_ASYNC         = 0x0001  # play asynchronously
    SND_NODEFAULT     = 0x0002  # silence (!default) if sound not found
    SND_MEMORY        = 0x0004  # pszSound points to a memory file
    SND_LOOP          = 0x0008  # loop the sound until next sndPlaySound
    SND_NOSTOP        = 0x0010  # don't stop any currently playing sound 

    SND_NOWAIT        = 8192    # don't wait if the driver is busy
    SND_ALIAS         = 65536   # name is a registry alias
    SND_ALIAS_ID      = 1114112 # alias is a predefined ID
    SND_FILENAME      = 131072  # name is file name
    SND_RESOURCE      = 262148  # name is resource name or atom

    SND_PURGE         = 0x0040  # purge non-static events for task
    SND_APPLICATION   = 0x0080  # look for application specific association
    
    API.new('Beep', 'LL', 'B')
    API.new('PlaySound', 'PPL', 'B', 'winmm')
    API.new('waveOutSetVolume', 'PL', 'I', 'winmm')
    API.new('waveOutGetVolume', 'LP', 'I', 'winmm')
    API.new('waveOutGetNumDevs', 'V', 'I', 'winmm')
    API.new('waveInGetNumDevs', 'V', 'I', 'winmm')
    API.new('midiOutGetNumDevs', 'V', 'I', 'winmm')
    API.new('midiInGetNumDevs', 'V', 'I', 'winmm')
    API.new('auxGetNumDevs', 'V', 'I', 'winmm')
    API.new('mixerGetNumDevs', 'V', 'I', 'winmm')
  end
end
