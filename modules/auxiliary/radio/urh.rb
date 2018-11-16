#metasploit

require 'msf/base'
require 'msf/core/auxiliary'
require 'msf/core/module'
require 'msf/core/opt_base'
require 'msf/core/opt_string'

class MetasploitModule < Msf::Auxiliary

  def initialize(info={})
    super(update_info(info,
                      'Name' => 'URH Command Line Interface',
                      'Description' => %q{
      This module is using the Universal Radio Hacker Command Line Interface. Universal Radio Hacker: A Suite for Analyzing and Attacking Stateful Wireless Protocols.
      for more information visit: https://github.com/jopohl/urh
      If you are not incorporated in URH at all. You should read first https://github.com/jopohl/urh/wiki/Command-Line-Interface.
      Use the URH GUI to improve CLI skills with URH.
      For this tool you have to install the URH you can download it with git: git clone https://github.com/jopohl/urh
                        },
                      'Author' => [ 'https://github.com/ChrisVisitGit '],
                      'Licence' => MSF_LICENSE
          ))
    register_options(
        [
           OptString.new('DEVICE',[true, 'The Device you use: R2, AirSpy Mini, Bladerf, FUNcube, HackRF, LimeSDR, RTL-SDR, RTL-TCP, SDRPlay, SoundCard, USRP', 'HackRF']),
           OptString.new('DEVICE_IDENTIFIER',[false, 'Device identifier','']),
           OptString.new('DEVICE_BACKEND',[true, 'native or gnuradio', 'native']),
           OptString.new('FREQUENCY',[true,'Frequency, default set on 433.92e6','433.92e6']),
           OptString.new('SAMPLERATE',[false,'Sample rate to use Default 2e6','1e6']),
           OptString.new('BANDWIDTH',[false,'Bandwidth to use (defaults to sample rate)','']),
           OptString.new('GAIN',[false,'RF gain the SDR shall use','']),
           OptString.new('IF_GAIN',[false,'Only supportet for ','']),
           OptString.new('BASEBAND_GAIN',[false, 'Baseband gain to use(only supportet for some SDRs','']),
           OptString.new('ADAPTIVE_NOISE',[false,'Use adaptive noise when receiving','']),
           OptString.new('MOD_CARRIER_FREQUENCY',[false,'Carrier frequency in Hertz default:1000','']),
           OptString.new('MOD_CARRIER_AMPLITUDE',[false,'Carrier amplitude default: 1','']),
           OptString.new('MOD_CARRIER_PHASE',[false,'Carrier phase in degree default: 0 ','']),
           OptString.new('MOD_TYPE',[false,'Modulation type must be one of ASK,FSK, PSK, GFSK default: FSK ','ASK']),
           OptString.new('MOD_PARAMETER_ZERO',[false,'Modulation parameter for zero','0']),
           OptString.new('MOD_PARAMETER_ONE',[false,'Modulation parameter for one','1']),
           OptString.new('BITLENGTH',[false,'Length of a bit in samples','']),
           OptString.new('PATH', [true, 'Add you parth to the url_cli.py like: home/name/urh/src/urh/cli/urh_cli.py', '']),
           OptString.new('NOISE',[false, 'Noise threshold default: 0.1. Used for RX only','']),
           OptString.new('CENTER',[false, 'Center between 0 and 1 for demodulation default: 0.. Used for RX only','']),
           OptString.new('TOLERANCE',[false,'Tolerance for demodulation in samples default: 5','']),
           OptString.new('HEX',[false,'Give messages as hex instead of bits set on "--hex" if you want to use','']),
           OptString.new('MOD_ENCODING',[false,'Specify encoding','']),
           OptString.new('MESSAGES',[false,'Messages to send. Give pauses after with a /. Separate with spaces e.g. 1001/42ms 1100/3ns 001 1111/200','']),
           OptString.new('FILENAME', [false, 'Insert a file Name for easy handling, the extension is ".complex", for receive. Hint, you have to change it if you dont want that it overwrite itself', '']),
           OptString.new('PAUSE',[false,'The default pause which is inserted after a every message which does not have a pause configured. (default: 250ms) Supported time units: s (second), ms (millisecond), µs (microsecond), ns (nanosecond) If you do not give a time suffix the pause is assumed to be in samples.','']),
           OptString.new('MODE',[true,'Enter RX or TX mode','rx']),
           OptString.new('RECEIVE_TIME',[false,'Enter RX mode default on 3s','']),
           OptString.new('RAW',[false,'Use raw mode i.e. send/receive IQ data instead of bits', '']),
           OptString.new('VERBOSE',[false,'Verbose',''])
       ])
end


  def run
   #init array's
   arr_rx_res = Array.new
   arr_tx_res = Array.new

   #fill receive array, tags and args,which we get from the datastore
   arr_rx_tags = "","-d","-di","-db","-f","-s","-b","-g","-if","-bb","-a","-bl","-n","-c","-t","-file","","-rt","","" #array with 20 fields
   arr_rx_args = datastore['PATH'],datastore['DEVICE'], datastore['DEVICE_IDENTIFIER'],datastore['DEVICE_BACKEND'],
                 datastore['FREQUENCY'], datastore['SAMPLERATE'],datastore['BANDWIDTH'],datastore['GAIN'],
                 datastore['IF_GAIN'], datastore['BASEBAND_GAIN'],datastore['ADAPTIVE_NOISE'],datastore['BITLENGTH'],
                 datastore['NOISE'], datastore['CENTER'],datastore['TOLERANCE'],datastore['FILENAME'],
                 datastore['MODE'],datastore['RECEIVE_TIME'],datastore['RAW'],datastore['VERBOSE']                     #array with 20 fields

   #fill the transmitarray,  tags and args,which we get from the datastore
   arr_tx_tags = "","-d","-di","-db","-f","-s","-b","-g","-if","-bb","-cf","-ca","-cp","-mo","-p0","-p1","-bl","","-e","-m","-file","-p","","","" #array with 25 fields
   arr_tx_args = datastore['PATH'], datastore['DEVICE'], datastore['DEVICE_IDENTIFIER'],datastore['DEVICE_BACKEND'],datastore['FREQUENCY'] ,datastore['SAMPLERATE'],
       datastore['BANDWIDTH'],datastore['GAIN'],datastore['IF_GAIN'],datastore['BASEBAND_GAIN'],datastore['MOD_CARRIER_FREQUENCY'],datastore['MOD_CARRIER_AMPLITUDE'],datastore['MOD_CARRIER_PHASE'],
       datastore['MOD_TYPE'],datastore['MOD_PARAMETER_ZERO'],datastore['MOD_PARAMETER_ONE'],datastore['BITLENGTH'],datastore['HEX'],datastore['MOD_ENCODING'],datastore['MESSAGES'],datastore['FILENAME'],
       datastore['PAUSE'], datastore['MODE'], datastore['RAW'],datastore['VERBOSE'] #array with 25 fields


    modestr = datastore['MODE']
   #find out which mode is running
   if modestr.eql? "rx"     # build string for rx out of arr_rx_tags and arr_rx_args
     arr_rx_args[16] = "-rx"
     if arr_rx_args[18].to_s.eql? "raw" or arr_rx_args[18].to_s.eql? "r" or arr_rx_args[18].to_s.eql? "-r" or arr_rx_args[18].to_s.eql? "--raw"   #raw only have the tag "-r" or "--raw"
       arr_rx_args[18] = "-r"
     end
     if arr_rx_args[19].to_s.eql? "verbose" or arr_rx_args[19].to_s.eql? "v" or arr_tx_args[19].to_s.eql? "-v" or arr_tx_args[19].to_s.eql? "--verbose" #verbose only have the tag "-v" or "--verbose"
       arr_rx_args[19] = "-v"#nutz das einfache v oder doch 3fach johannes fragen
     end
     for i in 0..20  #add both arrays to one which dont have any nil
       if arr_rx_args[i].to_s.empty?   #here we check the empty args, that we get a good result array for the output
         i = i+1
       elsif arr_rx_args[i] == arr_rx_args[16]    #ceck for -rx not doubled
         arr_rx_res[i] = arr_rx_args[16]
       elsif arr_rx_args[i] == arr_rx_args[18]    #check for -r not doubled
         arr_rx_res[i] = arr_rx_args[18]
       elsif arr_rx_args[i] == arr_rx_args[19]     # check for -v not doubled
         arr_rx_res[i] = arr_rx_args[19]
       else
         arr_rx_res[i] = arr_rx_tags[i],arr_rx_args[i]
       end
     end
     arr_rx_res[0] = datastore['PATH']
     arr_rx_print = arr_rx_res.delete_if { |a| a == /"/ || a.blank?}.to_s.delete("[],") #clean the """ and then check if they blank and then delete ths array, also delete the char values which are [] or ,

     print(arr_rx_print.to_s)  #check out what you will insert in the command line next
     print_blank_line
     system(arr_rx_print.to_s) # send it to the command line - finish here

   elsif modestr.eql? 'tx' # build string for tx out of arr_tx_tags and arr_tx_args
     arr_tx_args[22] = "-tx"

     if arr_tx_args[23].to_s.eql? "raw" or arr_tx_args[23].to_s.eql? "r" or arr_tx_args[23].to_s.eql? "-r" or arr_tx_args[23].to_s.eql? "--raw"
       arr_tx_args[23] = "-r"
     end
     if arr_tx_args[24].to_s.eql? "verbose" or arr_tx_args[24].to_s.eql? "v" or arr_tx_args[24].to_s.eql? "-v" or arr_tx_args[24].to_s.eql? "--verbose"
        arr_tx_args[24] = "-v" #nutz das einfache v oder doch 3fach johannes fragen
     end
     if arr_tx_args[17].to_s.eql? "hex" or arr_tx_args[17].to_s.eql? "h"  or arr_tx_args[17].to_s.eql? "--hex"
       arr_tx_args[17] = "--hex"
     end

     for i in 0..25  #add both arrays to one which dont have any nil
      if arr_tx_args[i].to_s.empty?
        i = i+1
      elsif arr_tx_args[i] ==arr_tx_args[22]
        arr_tx_res[i]= arr_tx_args[22]
      elsif arr_tx_args[i] ==arr_tx_args[23]
        arr_tx_res[i]= arr_tx_args[23]
      elsif arr_tx_args[i] ==arr_tx_args[24]
        arr_tx_res[i]= arr_tx_args[24]
      elsif arr_tx_args[i] ==arr_tx_args[17]
        arr_tx_res[i]= arr_tx_args[17]
      else
        arr_tx_res[i] = arr_tx_tags[i],arr_tx_args[i]
       end
     end
     arr_tx_res[0] = datastore['PATH']
     arr_tx_print = arr_tx_res.delete_if { |a| a == /"/ || a.blank?}.to_s.delete("[],")
     print(arr_tx_print.to_s)
     print_blank_line
     system(arr_tx_print.to_s().to_s)
   else
     print(datastore['MODE'].to_s)
   end
  end
end
