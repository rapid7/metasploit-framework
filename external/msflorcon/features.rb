#
# This class wraps the lorcon 802.11 packet injection library
#

class MSFLorcon

	# Symbol definitions for userstack interface
	LIBSYMBOLS = 
	{
		:msflorcon_setchannel    => 'IPI',
		:msflorcon_getchannel    => 'IP',
		:msflorcon_send          => 'IPPIII',
		:msflorcon_close         => '0P',
		:msflorcon_open          => 'IPPPI',
		:msflorcon_driverlist    => 'IPI',
		:msflorcon_in_tx_size    => 'I',			
	}

	LIBSYMBOLS.each_pair { |name, args| LORCON::SYM[name] = LORCON::LIB[name.to_s, args] }

		
	def self.driverlist
		buff = DL.malloc(1024)
		r, rs = LORCON::SYM[:msflorcon_driverlist].call(buff, buff.size)
		r == 1 ? buff.to_str.gsub("\x00", '').split(",") : []
	end
	
	def self.open(iface='ath0', driver='madwifi', channel=11)
		r, rs = LORCON::SYM[:msflorcon_in_tx_size].call()
		tx = DL.malloc(r)	
		r, rs = LORCON::SYM[:msflorcon_open].call(tx, iface, driver, channel)
		r == 1 ? Interface.new(tx) : nil
	end

	class Interface
		attr_accessor :tx
		
		def initialize(tx)
			self.tx = tx
		end
		
		def close
			r, rs = LORCON::SYM[:msflorcon_close].call(self.tx)
		end
		
		def write(buff, count=1, delay=0)
			r, rs = LORCON::SYM[:msflorcon_send].call(self.tx, buff.to_ptr, buff.length, count, delay)
			return r
		end
		
		def channel(chan=nil)
			if (chan)
				r, rs = LORCON::SYM[:msflorcon_setchannel].call(self.tx, chan)
			else
				r, rs = LORCON::SYM[:msflorcon_getchannel].call(self.tx)
			end
		end
		
	end	
	

end
