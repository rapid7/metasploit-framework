module Net # :nodoc:
  module DNS 
    
    class RR
      
      #
      # This is an auxiliary class to hadle RR class field in a DNS packet. 
      #
      class Classes
        
        # An hash with the values of each RR class stored with the 
        # respective id number
        Classes = {
          'IN'        => 1,       # RFC 1035
          'CH'        => 3,       # RFC 1035
          'HS'        => 4,       # RFC 1035
          'NONE'      => 254,     # RFC 2136
          'ANY'       => 255,     # RFC 1035
        }
        
        # The default value when class is nil in Resource Records
        @@default = Classes["IN"]

        # Be able to control the default class to assign when
        # cls argument is +nil+. Default to +IN+
        def self.default=(str)
          if Classes.has_key? str
            @@default = Classes[str]
          else
            raise ClassArgumentError, "Unknown class #{str}"
          end
        end

        # Checks whether +cls+ is a valid RR class.  
        def self.valid?(cls)
          case cls
          when String
            return Classes.has_key?(cls)
          when Fixnum
            return Classes.invert.has_key?(cls)
          else
            raise ClassArgumentError, "Wrong cls class: #{cls.class}"
          end
        end
        
        # Returns the class in string format, as "IN" or "CH",
        # given the numeric value
        def self.to_str(cls)
          case cls
          when Fixnum
            if Classes.invert.has_key? cls
              return Classes.invert[cls]
            else
              raise ClassArgumentError, "Unknown class number #{cls}"
            end
          else
            raise ClassArgumentError, "Wrong cls class: #{cls.class}"
          end
        end

        # Gives in output the keys from the +Classes+ hash
        # in a format suited for regexps
        def self.regexp
          Classes.keys.join("|")
        end

        # Creates a new object representing an RR class. Performs some
        # checks on the argument validity too. Il +cls+ is +nil+, the
        # default value is +ANY+ or the one set with Classes.default=
        def initialize(cls)
          case cls
          when String
            # type in the form "A" or "NS"
            new_from_string(cls.upcase) 
          when Fixnum
            # type in numeric form
            new_from_num(cls) 
          when nil
            # default type, control with Classes.default=
            @str = Classes.invert[@@default] 
            @num = @@default
          else
            raise ClassArgumentError, "Wrong cls class: #{cls.class}"
          end
        end

        # Constructor for string data class,
        # *PRIVATE* method
        def new_from_string(cls)
          case cls
          when /^CLASS\\d+/
            # TODO!!!
          else 
            # String with name of class
            if Classes.has_key? cls
              @str = cls
              @num = Classes[cls]
            else
              raise ClassesArgumentError, "Unknown cls #{cls}"
            end
          end
        end

        # Contructor for numeric data class
        # *PRIVATE* method
        def new_from_num(cls)
          if Classes.invert.has_key? cls
            @num = cls
            @str = Classes.invert[cls]
          else
            raise ClassesArgumentError, "Unkown cls number #{cls}"
          end
        end
        
        # Returns the class in number format 
        # (default for normal use)
        def inspect
          @num
        end

        # Returns the class in string format,
        # i.d. "IN" or "CH" or such a string.
        def to_s
          @str
        end
        
        # Returns the class in numeric format,
        # usable by the pack methods for data transfers
        def to_i
          @num.to_i
        end


        # Should be used only for testing purpouses
        def to_str
          @num.to_s
        end

        private :new_from_num, :new_from_string

      end # class Classes
    
    end # class RR
  end # module DNS
end # module Net

class ClassArgumentError < ArgumentError # :nodoc:
end
