module Rex
module Proto
module DCERPC
module Exceptions

class Error < ::RuntimeError
    @@errors = {}
	def initialize(*args)
		super(*args)
        if @@errors.size == 0
            _load_errors(File.join(File.dirname(__FILE__),'errors.txt'))
        end
	end

    # loads errors.txt
    def _load_errors(file)
        File.open(file).each { |line|
            next if line =~ /^#/
            code, string = line.split
            code = [code].pack('H*').unpack('L')[0]
            @@errors[code] = string
        }
    end

    # returns an error string if it exists, otherwise just the error code
    def get_error (error)
        string = ''
        if @@errors[error]
            string = @@errors[error]
        else
            string = sprintf('0x%.8x',error)
        end
    end
end

class Fault < Error
	attr_accessor :fault
    def to_s
        'DCERPC FAULT => ' + get_error(self.fault)
    end
end

class NoResponse < Error
    def to_s
        'no response from dcerpc service'
    end
end

class InvalidPacket < Error
    def initialize(message = nil)
        @message = message
    end
    
    def to_s
        str = 'Invalid packet.'
        if (@message)
            str += " #{@message}"
        end
    end
end

end
end
end
end
