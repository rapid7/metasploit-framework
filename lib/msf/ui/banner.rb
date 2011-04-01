module Msf
module Ui

###
#
# Module that contains some most excellent banners.
#
###
module Banner

	Logos =
		[
'
                ##                          ###           ##    ##
 ##  ##  #### ###### ####  #####   #####    ##    ####        ######
####### ##  ##  ##  ##         ## ##  ##    ##   ##  ##   ###   ##
####### ######  ##  #####   ####  ##  ##    ##   ##  ##   ##    ##
## # ##     ##  ##  ##  ## ##      #####    ##   ##  ##   ##    ##
##   ##  #### ###   #####   #####     ##   ####   ####   #### ###
                                      ##
',
'
                _                  _       _ _
               | |                | |     (_) |
 _ __ ___   ___| |_ __ _ ___ _ __ | | ___  _| |_
| \'_ ` _ \ / _ \ __/ _` / __| \'_ \| |/ _ \| | __|
| | | | | |  __/ || (_| \__ \ |_) | | (_) | | |_
|_| |_| |_|\___|\__\__,_|___/ .__/|_|\___/|_|\__|
                            | |
                            |_|
',
# jbl
'
                __.                       .__.        .__. __.
  _____   _____/  |______    ____________ |  |   ____ |__|/  |_
 /     \_/ __ \   __\__  \  /  ___/\____ \|  |  /  _ \|  \   __\
|  Y Y  \  ___/|  |  / __ \_\___ \ |  |_> >  |_(  <_> )  ||  |
|__|_|  /\___  >__| (____  /____  >|   __/|____/\____/|__||__|
      \/     \/          \/     \/ |__|
',
# colossal
'
                     888                           888        d8b888
                     888                           888        Y8P888
                     888                           888           888
88888b.d88b.  .d88b. 888888 8888b. .d8888b 88888b. 888 .d88b. 888888888
888 "888 "88bd8P  Y8b888       "88b88K     888 "88b888d88""88b888888
888  888  88888888888888   .d888888"Y8888b.888  888888888  888888888
888  888  888Y8b.    Y88b. 888  888     X88888 d88P888Y88..88P888Y88b.
888  888  888 "Y8888  "Y888"Y888888 88888P\'88888P" 888 "Y88P" 888 "Y888
                                           888
                                           888
                                           888
',
'
                 o                       8         o   o
                 8                       8             8
ooYoYo. .oPYo.  o8P .oPYo. .oPYo. .oPYo. 8 .oPYo. o8  o8P
8\' 8  8 8oooo8   8  .oooo8 Yb..   8    8 8 8    8  8   8
8  8  8 8.       8  8    8   \'Yb. 8    8 8 8    8  8   8
8  8  8 `Yooo\'   8  `YooP8 `YooP\' 8YooP\' 8 `YooP\'  8   8
..:..:..:.....:::..::.....::.....:8.....:..:.....::..::..:
::::::::::::::::::::::::::::::::::8:::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
',
'
                                  _       _
             _                   | |     (_)_
 ____   ____| |_  ____  ___ ____ | | ___  _| |_
|    \ / _  )  _)/ _  |/___)  _ \| |/ _ \| |  _)
| | | ( (/ /| |_( ( | |___ | | | | | |_| | | |__
|_|_|_|\____)\___)_||_(___/| ||_/|_|\___/|_|\___)
                           |_|
',
# cowsay++
'
 ____________
< metasploit >
 ------------
       \   ,__,
        \  (oo)____
           (__)    )\
              ||--|| *
',
'
                                  _
                                 | |      o
 _  _  _    _ _|_  __,   ,    _  | |  __    _|_
/ |/ |/ |  |/  |  /  |  / \_|/ \_|/  /  \_|  |
  |  |  |_/|__/|_/\_/|_/ \/ |__/ |__/\__/ |_/|_/
                           /|
                           \|
',
'
#    # ###### #####   ##    ####  #####  #       ####  # #####
##  ## #        #    #  #  #      #    # #      #    # #   #
# ## # #####    #   #    #  ####  #    # #      #    # #   #
#    # #        #   ######      # #####  #      #    # #   #
#    # #        #   #    # #    # #      #      #    # #   #
#    # ######   #   #    #  ####  #      ######  ####  #   #
',
'
                |                    |      _) |
 __ `__ \   _ \ __|  _` |  __| __ \  |  _ \  | __|
 |   |   |  __/ |   (   |\__ \ |   | | (   | | |
_|  _|  _|\___|\__|\__,_|____/ .__/ _|\___/ _|\__|
                              _|
'
		]

	#
	# Returns a random metasploit logo.
	#
	def self.to_s_original
		if ENV['GOCOW']
			Logos[6]
		else
			Logos[rand(Logos.length)]
		end
	end

	def self.to_s
		if (ENV["WINFOOL"] or ( RUBY_PLATFORM =~ /win32|cygwin|ming/i and not ENV['LINFOOL'] ))
			%q{
			ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH5NTU1NTU1NTU1NTU1N
			TU1+ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAg
			ICAgICAgICAgICAgICAgICAgfk1NTU06ICAgICAgICAgICAgIDpNTU1NfiAg
			ICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAg
			ICAgICBNTU0gICxNTU1NTU1NWX5+fllNTSx+TU1NTU0gICBJTU0gICAgICAg
			ICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgID9JTTcsLEla
			NzckSSwgICAgICAgTVlZNyAgICAgSU1NN003Liw3TUlJLiAgICAgICAgICAg
			ICAgICAgICAKICAgICAgICAgICAgICAgICAsTU0gIDpNTSAgO01NWSQgICAg
			ICAgTW1tbSAgICAsTSwsSjgsTUlJIC5NTSwgICAgICAgICAgICAgICAgICAK
			ICAgICAgICAgICAgIC4sTU0uLE1NICAgICAgLk1MLkpNLiAgICAgTSAgICAg
			IC5NTThETTsuICAgSU1NLi5NTSwuICAgICAgICAgICAgICAKICAgICAgICAg
			ICAgLk06LE1NLiBNTi4gICAgIC5NTC5NOi4gICAgTU1NOi4uLk1NIC44LiAg
			ICAgIElNOk1NLi5NTy4gICAgICAgICAgICAKICAgICAgICAgICAgTTcsTSwg
			ICAgT34gICAgICBZTU1JLiAgTU1NLi4uLE1NTUQuIC5NfiAgICAgTU06WUQs
			TSwgTSwuICAgICAgICAgICAKICAgICAgICAgIE1NICQuICAgICAgIE1NLiAg
			ICAgIC5NTU0gLi4uLi4uLi4uLiAgTU1NICAgICBNTS4gICAgICBNLE1NLiAg
			ICAgICAgICAKICAgICAgICAsTSQsST0uICAgICAgIC5aOy4gICAgIE0kLi4u
			Li4uPz8/Pz8/LiAuLiAkJE1+LiQkLiAgICAgICAuTiwkTSwgICAgICAgICAK
			ICAgICAgLjpNLixNIEk4LiAgIC4sICAgICAgICAuTU1NICAgICAgICAgICAg
			TU1NTSAgICBJICAgICAgICAgIC5NTCAuLk0sICAgICAgICAKICAgICAuTSwg
			TTogICAuWUwuSk0gICAgICAgTk0uICAuTS4gICAgLiAgICAgICAgICAuTU0g
			IE0gICAgICAgIEo4TU06TS46TSAgICAgICAKICAgIC5NLDpNLCAgICAgIDo6
			YCAgICAgICA9fiAgLi4gIE0gIC4uIC4uIC4gICAgLi4uIDo3RC5NLiAgICAu
			TllgICAgIE0sLE0uICAgICAKICAgIE1+IE0gICAgICAgICAgICAgICAgICB+
			LCAgICAgIC5NICAgIC4gICAgICAgICAgICAgTS5NTSAgICAgICAgICAgICBN
			IH5NICAgICAKICAsTTouTSAgICAgICAgICAgICAgICAgLk1PICAgICAgIE0g
			ICAgIFpNLiAgTU1NLiAgIC4gICAgTS4gICAgICAgICAgICAgTSA6TSAgICAK
			IC49Ty5NWiAgICAgICAgICAgICAgICAgLk0gICAgICAuP1ouICAgICA3Wlpa
			WiAuWisrK0lEWlorLk0gICAgICAgICAgICAgWk0uTysgICAKIC5NIE1NICAg
			ICAgICAgICAgICAgICAgOk04LiAgICAgIE0gICAgICAgICAgICAgICAgICAg
			ICAgTU1NLiAgICAgICAgICAgLE1NIE0gICAKLk0uLk0gICAgICAgICAgICAg
			ICAgICAgTSAgLk1NLiAgIE1NICAgOyAgICAgICAgICAgICAgICAgLk1NICAg
			ICAgICAgICAgICBNLC5NICAKN00gTSAgICAgICAgICAgICAgICAgICBETSA9
			RCwsRC4gICBNTSAgICAgICBEREREICAgICAgICAgIDpNICAgICAgICAgICAg
			ICAuTS5NRCAKTy4sTSAgICAgICAgICAgICAgICAgICBNICB+LE1NTSwgICBN
			TS4gICAuTU0sLi5NTU1NICAgICAgICBNICAgICAgICAgICAgICAgTSwuTSAK
			Ty5NICAgICAgICAgICAgICAgICAgLk0gICAuICAgICAgICAgLk0gICAuTSAg
			ICAgLi4gIE1NTU1NTU1NICAgICAgICAgICAgICAgLk0uTS4KOCxNICAgICAg
			ICAgICAgICAgICA9TSAgICAgICAgICAgICAgLk89PT1NTy4gICAgPSAgICAg
			ICAgICBaTSAgICAgICAgICAgICAgIE0uT00KPU1NICAgICAgICAgICAgICAg
			ICBNICBNTU0gICAgICAgICAuIC4uIDtNIC4gICAsTU0uICAgIC4gICAgLk0g
			ICAgICAgICAgICAgIE1NIE0KPU0gICAgICAgICAgICAgICAgICxNICAgOiA4
			ICAgICAgICAgIC4gICBNIE1NTSAuLk0gICAgICAgICAgLk0gICAgICAgICAg
			ICAgIC5NIE0KPU0gICAgICAgICAgICAgICAgICB+fn5NPX5+ICAgICAgICAg
			OC4gICBNIC44OE06fi4gICAgICAgICAgLk0gICAgICAgICAgICAgIC5NIE0K
			PU0gICAgICAgICAgICAgICAgICAgICBpLi4gICAgICAgICAgLk0uTU1NTU1N
			TSBNTU0uLiAuLiAgIC4gIE0gICAgICAgICAgICAgIC5NIE0KPU0gICAgICAg
			ICAgICAgICAgICAgICBNTUJiLiAgICAgICAgICAgTStNTU0uLk0uICAgIC5N
			TSAuLi5NTSAgICAgICAgICAgICAgICBNIE0KPU0gICAgICAgICAgICAgICAg
			ICAgICBNICAgICAgICAgICAgLn5NODpPICAgIDgrfiAgICAgTzhNODg4ICAg
			ICAgICAgICAgICAgIC5NIE0KPU0gICAgICAgICAgICAgICAgICAgICBNIC4g
			ICAgICAgICBNTS4gIE8gICAgICAgTS4gICAgICAgTSAgICAgICAgICAgICAg
			ICAgIC5NIE0KPTpNICAgICAgICAgICAgICAgICAgICBNICAuTiAgLE1NLCAg
			LiBNTSAgICAgICAgLk1NICAgICBNLiAgICAgICAgICAgICAgICAgIE06IE0K
			OC5NICAgICAgICAgICAgICAgICAgICBNTT09PT09PSAgICAuT00rIC4gIC4g
			ICAgLiAgK1ogIC5NLiAgICAgICAgICAgICAgICAgIE0gT00KTy5NLCAgICAg
			ICAgICAgICAgICAgICAgLk1NOywuICAuLi5NTS4gICAgICAgICAgICAgIE0g
			ICBNTSAgICAgICAgICAgICAgICAgLE0uTS4KTy4gTSAgICAgICAgICAgICAg
			ICAgICAgICAgICBNTU1NICAgICAgICAgICAgICAgICAgICA3ICAgTSAsTU1N
			TSAgICAgICAgICAuTS4gTSAKJE0gTTogICAsPT09LjpOOk1NfkQrLiA9PSw/
			TiAgLk0uLiAgICAgICAgICAgICAgICAgLiA3Li4uTX4sLi4uLk0gICAgICAg
			ICB+TS5NRC4KLk0gIE0gICB+TU1NIDpNTSAuTTp+fiBNTU09TS4gLk0gICAg
			ICAgICAgICAgICAgICAgICBJICBNLk0gTU1NTU0gICAgICAgICxNLi5NICAK
			IC5NICxNICAgICAgICAgICAgICAgICAgICAgICAgICBNICAgICAgICAgICAg
			ICAgICAgICAgIE0gTU1NIE1NTU0gOE4gICAgLk0sLk0uICAKICArTyA/TyAg
			ICAgIElNTU1NIE1NTU1JSSAgICAgICArTS4uICAgICAgICAgICAgICAgICAg
			IC5JKyArTVogIE0gTU0gICAgWj8uTysgICAKICAgTTouTSwgICAgIDpNIE1N
			TU1NTU06OiAgICAgICAgTS4gICAgICAgICAgICAgICAgICAgICAuTSAgLk1N
			IE0gICAgICAuTSA6TSAgICAKICAgIE1+IE06ICAgICAgICAgICAgICAgICAg
			ICAgICAgTS4gICAgICAgICAgICAgICAgICAgICAgTSAgICAgTSAgICAgIH5N
			Ln5NICAgICAKICAgICBNLC5OICAgICAgICAgICAgICAgICAgICAgICA7Ti4g
			ICAgICAgICAgICAgICAgICAgICAgIE0gLiBNTiAgICAufk4gOk0gICAgICAK
			ICAgICAgTTogfk0gICAgICAgICAgICAgICAgICAgICBNICAgICAgICAgICAg
			ICAgICAgICAgICAgIE0uTU1NICAgIC5NTS46TSAgICAgICAKICAgICAgICxN
			LiBNOiAgICAgICAgICAgICAgICAgLk0uICAgICAgICAgICAgICAgICAgICAg
			IE1NLC4gICAgICAgLk0gIE0sICAgICAgICAKICAgICAgICAsTSQuPz8uICAg
			ICAgICAgICAgICAgTSAgICAgICAgICAgICAuICAgLiAuJCQ4SS4gICAgICAg
			LiAsWi4kTSwgICAgICAgICAKICAgICAgICAgIE1NIElNLiAgICAgICAgICAg
			LkpUVE1NIG0gICAgICAgICBfLk1NTU1NICAgICAgICAgLi4uIE1NLk1NICAg
			ICAgICAgICAKICAgICAgICAgICAuTTcuTU0uICAgICAgICA7Tk1tLiAgIG14
			LCAgTVRUdGAgICAgTU1NfiAgICAgICAgIC5NTS4gTSwuICAgICAgICAgICAK
			ICAgICAgICAgICAgIE06ICxOfi4gICAgICAuWlQgICAgV0suTS4gIDpOTk0g
			ICA6TSBNTSAgICAgIC4uPU0sLixNWi4gICAgICAgICAgICAKICAgICAgICAg
			ICAgICAgTU0uLjpNTS4gIC5NVCAgICAgIFlNTS4gICAsTU0gICAgICxNICAg
			ICwuTU06Li5NTTstICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAs
			TU0uLiA6TU0sICAgICAgbW07TSAgIE86IE06ICAgIE5NTS43TTogLi5NTSwu
			ICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgIElJTTcsICxJ
			N1o3NzcgIElJICAgICA/SUkgICA3NzckN0k9ICw3TUlJICAgICAgICAgICAg
			ICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICBNTU0gICAgLE1NTU1N
			TU1NTU1NTU1NTU1NLCAgICBJTU0gICAgICAgICAgICAgICAgICAgICAgICAK
			ICAgICAgICAgICAgICAgICAgICAgICAgICAgOk1NTU06ICAgICAgICAgICAg
			ICxNTU1NfiAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAg
			ICAgICAgICAgICAgICAgICAgICAgIH5NTU1NTU1NTU1NTU1NTU1+ICAgICAg
			ICAgICAgICAgICAgICAgICAgICAgICAgICAK
			}.unpack('m').first
		else
			to_s_original
		end
	end

end

end
end

