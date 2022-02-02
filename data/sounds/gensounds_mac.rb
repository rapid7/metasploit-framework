sounds = {
  'num0' => '0',
  'num1' => '1',
  'num2' => '2',
  'num3' => '3',
  'num4' => '4',
  'num5' => '5',
  'num6' => '6',
  'num7' => '7',
  'num8' => '8',
  'num9' => '9',
  'closed' => 'closed',
  'opened' => 'opened',
  'plugin_load' => 'meta sploit sound plugin has been loaded',
  'plugin_unload' => 'sound plugin has been unloaded',
  'session' => 'session',
  'address' => 'address',
  'port'    => 'port',
  'dot'     => 'dot',
  'session_open_meterpreter' => 'a new meterp reter session has been opened',
  'session_open_shell' => 'a new command shell session has been opened',
  'session_open_vnc'	=> 'a new VNC session has been opened'
}

voice_name = 'Zarvox'

def create_aiff(voice, file,text)
  system("say -v #{voice} -o #{file}.aiff #{text}")
end

sounds.keys.each do |k|
  create_aiff(voice_name, k, sounds[k])
end

