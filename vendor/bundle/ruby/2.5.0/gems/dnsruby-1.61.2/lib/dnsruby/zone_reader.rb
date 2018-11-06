# --
# Copyright 2009 Nominet UK
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

# This class provides the facility to load a zone file.
# It can either process one line at a time, or return an entire zone as a list of
# records.
module Dnsruby
  class ZoneReader
    class ParseException < Exception

    end
    #  Create a new ZoneReader. The zone origin is required. If the desired SOA minimum
    #  and TTL are passed in, then they are used as default values.
    def initialize(origin, soa_minimum = nil, soa_ttl = nil)
      @origin = origin.to_s

      if (!Name.create(@origin).absolute?)
        @origin = @origin.to_s + "."
      end
      @soa_ttl = soa_ttl
      if (soa_minimum && !@last_explicit_ttl)
        @last_explicit_ttl = soa_minimum
      else
        @last_explicit_ttl = 0
      end
      @last_explicit_class = Classes.new("IN")
      @last_name = nil
      @continued_line = nil
      @in_quoted_section = false
    end

    #  Takes a filename string, or any type of IO object, and attempts to load a zone.
    #  Returns a list of RRs if successful, nil otherwise.
    def process_file(source)
      if source.is_a?(String)
        File.open(source) do |file|
          process_io(file)
        end
      else
        process_io(source)
      end
    end

    #  Iterate over each line in a IO object, and process it.
    #  Returns a list of RRs if successful, nil otherwise.
    def process_io(io)
      zone = nil
      io.each do |line|
        begin
          ret = process_line(line)
          if (ret)
            rr = RR.create(ret)
            if (!zone)
              zone = []
            end
            zone.push(rr)
          end
        rescue Exception => e
          raise ParseException.new("Error reading line #{io.lineno} of #{io.inspect} : [#{line}]")
        end
      end
      return zone
    end

    #  Process the next line of the file
    #  Returns a string representing the normalised line.
    def process_line(line, do_prefix_hack = false)
      return nil if (line[0,1] == ";")
      line = strip_comments(line)
      return nil if (line.strip.length == 0)
      return nil if (!line || (line.length == 0))
      @in_quoted_section = false if !@continued_line

      if (line.index("$ORIGIN") == 0)
        @origin = line.split()[1].strip #  $ORIGIN <domain-name> [<comment>]
        #                 print "Setting $ORIGIN to #{@origin}\n"
        return nil
      end
      if (line.index("$TTL") == 0)
        @last_explicit_ttl = get_ttl(line.split()[1].strip) #  $TTL <ttl>
        #                 print "Setting $TTL to #{ttl}\n"
        return nil
      end
      if (@continued_line)
        #  Add the next line until we see a ")"
        #  REMEMBER TO STRIP OFF COMMENTS!!!
        @continued_line = strip_comments(@continued_line)
        line = @continued_line.rstrip.chomp + " " + line
        if (line.index(")"))
          #  OK
          @continued_line = false
        end
      end
      open_bracket = line.index("(")
      if (open_bracket)
        #  Keep going until we see ")"
        index = line.index(")")
        if (index && (index > open_bracket))
          #  OK
          @continued_line = false
        else
          @continued_line = line
        end
      end
      return nil if @continued_line

      line = strip_comments(line) + "\n"

      #  If SOA, then replace "3h" etc. with expanded seconds
      #       begin
      return normalise_line(line, do_prefix_hack)
      #       rescue Exception => e
      #         print "ERROR parsing line #{@line_num} : #{line}\n"
      #         return "\n", Types::ANY
      #       end
    end

    def strip_comments(line)
      last_index = 0
      #  Are we currently in a quoted section?
      #  Does a quoted section begin or end in this line?
      #  Are there any semi-colons?
      #  Ary any of the semi-colons inside a quoted section?
      #  Handle escape characters
      if (line.index"\\")
        return strip_comments_meticulously(line)
      end
      while (next_index = line.index(";", last_index + 1))
        #  Have there been any quotes since we last looked?
        process_quotes(line[last_index, next_index - last_index])

        #  Now use @in_quoted_section to work out if the ';' terminates the line
        if (!@in_quoted_section)
          return line[0,next_index]
        end

        last_index = next_index
      end
      #  Check out the quote situation to the end of the line
      process_quotes(line[last_index, line.length-1])

      return line
    end

    def strip_comments_meticulously(line)
      #  We have escape characters in the text. Go through it character by
      #  character and work out what's escaped and quoted and what's not
      escaped = false
      quoted = false
      pos = 0
      line.each_char {|c|
        if (c == "\\")
          if (!escaped)
            escaped = true
          else
            escaped = false
          end
        else
          if (escaped)
            if (c >= "0" && c <= "9") # rfc 1035 5.1 \DDD
              pos = pos + 2
            end
            escaped = false
            next
          else
            if (c == "\"")
              if (quoted)
                quoted = false
              else
                quoted = true
              end
            else
              if (c == ";")
                if (!quoted)
                  return line[0, pos+1]
                end
              end
            end
          end
        end
        pos +=1
      }
      return line
    end

    def process_quotes(section)
      #  Look through the section of text and set the @in_quoted_section
      #  as it should be at the end of the given section
      last_index = 0
      while (next_index = section.index("\"", last_index + 1))
        @in_quoted_section = !@in_quoted_section
        last_index = next_index
      end
    end

    #  Take a line from the input zone file, and return the normalised form
    #  do_prefix_hack should always be false
    def normalise_line(line, do_prefix_hack = false)
      #  Note that a freestanding "@" is used to denote the current origin - we can simply replace that straight away
      #  Remove the ( and )
      #  Note that no domain name may be specified in the RR - in that case, last_name should be used. How do we tell? Tab or space at start of line.

      #  If we have text in the record, then ignore that in the parsing, and stick it on again at the end
      stored_line = "";
      if (line.index('"') != nil)
          stored_line = line[line.index('"'), line.length];
          line = line [0, line.index('"')]
      end
      if ((line[0,1] == " ") || (line[0,1] == "\t"))
        line = @last_name + " " + line
      end
      line.chomp!
      line.sub!(/\s+@$/, " #{@origin}") # IN CNAME @
      line.sub!(/^@\s+/, "#{@origin} ") # IN CNAME @
      line.sub!(/\s+@\s+/, " #{@origin} ")
      line.strip!


      #  o We need to identify the domain name in the record, and then
      split = line.split(' ') # split on whitespace
      name = split[0].strip
      if (name.index"\\")

        ls =[]
        Name.create(name).labels.each {|el| ls.push(Name.decode(el.to_s))}
        new_name = ls.join('.')


        if (!(/\.\z/ =~ name))
          new_name += "." + @origin
        else
          new_name += "."
        end
        line = new_name + " "
        (split.length - 1).times {|i| line += "#{split[i+1]} "}
        line += "\n"
        name = new_name
        split = line.split
        #  o add $ORIGIN to it if it is not absolute
      elsif !(/\.\z/ =~ name)
        new_name = name + "." + @origin
        line.sub!(name, new_name)
        name = new_name
        split = line.split
      end

      #  If the second field is not a number, then we should add the TTL to the line
      #  Remember we can get "m" "w" "y" here! So need to check for appropriate regexp...
      found_ttl_regexp = (split[1]=~/^[0-9]+[smhdwSMHDW]/)
      if (found_ttl_regexp == 0)
        #  Replace the formatted ttl with an actual number
        ttl = get_ttl(split[1])
        line = name + " #{ttl} "
        @last_explicit_ttl = ttl
        (split.length - 2).times {|i| line += "#{split[i+2]} "}
        line += "\n"
        split = line.split
      elsif (((split[1]).to_i == 0) && (split[1] != "0"))
        #  Add the TTL
        if (!@last_explicit_ttl)
          #  If this is the SOA record, and no @last_explicit_ttl is defined,
          #  then we need to try the SOA TTL element from the config. Otherwise,
          #  find the SOA Minimum field, and use that.
          #  We should also generate a warning to that effect
          #  How do we know if it is an SOA record at this stage? It must be, or
          #  else @last_explicit_ttl should be defined
          #  We could put a marker in the RR for now - and replace it once we know
          #  the actual type. If the type is not SOA then, then we can raise an error
          line = name + " %MISSING_TTL% "
        else
          line = name + " #{@last_explicit_ttl} "
        end
        (split.length - 1).times {|i| line += "#{split[i+1]} "}
        line += "\n"
        split = line.split
      else
        @last_explicit_ttl = split[1].to_i
      end

      #  Now see if the clas is included. If not, then we should default to the last class used.
      begin
        klass = Classes.new(split[2])
        @last_explicit_class = klass
      rescue ArgumentError
        #  Wasn't a CLASS
        #  So add the last explicit class in
        line = ""
        (2).times {|i| line += "#{split[i]} "}
        line += " #{@last_explicit_class} "
        (split.length - 2).times {|i| line += "#{split[i+2]} "}
        line += "\n"
        split = line.split
      rescue Error => e
      end

      #  Add the type so we can load the zone one RRSet at a time.
      type = Types.new(split[3].strip)
      is_soa = (type == Types::SOA)
      type_was = type
      if (type == Types.RRSIG)
        #  If this is an RRSIG record, then add the TYPE COVERED rather than the type - this allows us to load a complete RRSet at a time
        type = Types.new(split[4].strip)
      end

      type_string=prefix_for_rrset_order(type, type_was)
      @last_name = name

      if !([Types::NAPTR, Types::TXT].include?type_was)
        line.sub!("(", "")
        line.sub!(")", "")
      end

      if (is_soa)
        if (@soa_ttl)
          #  Replace the %MISSING_TTL% text with the SOA TTL from the config
          line.sub!(" %MISSING_TTL% ", " #{@soa_ttl} ")
        else
          #  Can we try the @last_explicit_ttl?
          if (@last_explicit_ttl)
            line.sub!(" %MISSING_TTL% ", " #{@last_explicit_ttl} ")
          end
        end
        line = replace_soa_ttl_fields(line)
        if (!@last_explicit_ttl)
          soa_rr = Dnsruby::RR.create(line)
          @last_explicit_ttl = soa_rr.minimum
        end
      end

      line = line.strip

      if (stored_line && stored_line != "")
        line += " " + stored_line.strip
      end

      #  We need to fix up any non-absolute names in the RR
      #  Some RRs have a single name, at the end of the string -
      #    to do these, we can just check the last character for "." and add the
      #    "." + origin string if necessary
      if ([Types::MX, Types::NS, Types::AFSDB, Types::NAPTR, Types::RT,
            Types::SRV, Types::CNAME, Types::MB, Types::MG, Types::MR,
            Types::PTR, Types::DNAME].include?type_was)
        #         if (line[line.length-1, 1] != ".")
        if (!(/\.\z/ =~ line))
          line = line + "." + @origin.to_s
        end
      end
      #  Other RRs have several names. These should be parsed by Dnsruby,
      #    and the names adjusted there.
      if ([Types::MINFO, Types::PX, Types::RP].include?type_was)
        parsed_rr = Dnsruby::RR.create(line)
        case parsed_rr.type
        when Types::MINFO
          if (!parsed_rr.rmailbx.absolute?)
            parsed_rr.rmailbx = parsed_rr.rmailbx.to_s + "." + @origin.to_s
          end
          if (!parsed_rr.emailbx.absolute?)
            parsed_rr.emailbx = parsed_rr.emailbx.to_s + "." + @origin.to_s
          end
        when Types::PX
          if (!parsed_rr.map822.absolute?)
            parsed_rr.map822 = parsed_rr.map822.to_s + "." + @origin.to_s
          end
          if (!parsed_rr.mapx400.absolute?)
            parsed_rr.mapx400 = parsed_rr.mapx400.to_s + "." + @origin.to_s
          end
        when Types::RP
          if (!parsed_rr.mailbox.absolute?)
            parsed_rr.mailbox = parsed_rr.mailbox.to_s + "." + @origin.to_s
          end
          if (!parsed_rr.txtdomain.absolute?)
            parsed_rr.txtdomain = parsed_rr.txtdomain.to_s + "." + @origin.to_s
          end
        end
        line = parsed_rr.to_s
      end
      if (do_prefix_hack)
        return line + "\n", type_string, @last_name
      end
      return line+"\n"
    end

    #  Get the TTL in seconds from the m, h, d, w format
    def get_ttl(ttl_text_in)
      #  If no letter afterwards, then in seconds already
      #  Could be e.g. "3d4h12m" - unclear if "4h5w" is legal - best assume it is
      #  So, search out each letter in the string, and get the number before it.
      ttl_text = ttl_text_in.downcase
      index = ttl_text.index(/[whdms]/)
      if (!index)
        return ttl_text.to_i
      end
      last_index = -1
      total = 0
      while (index)
        letter = ttl_text[index]
        number = ttl_text[last_index + 1, index-last_index-1].to_i
        new_number = 0
        case letter
        when 115 then # "s"
          new_number = number
        when 109 then # "m"
          new_number = number * 60
        when 104 then # "h"
          new_number = number * 3600
        when 100 then # "d"
          new_number = number * 86400
        when 119 then # "w"
          new_number = number * 604800
        end
        total += new_number

        last_index = index
        index = ttl_text.index(/[whdms]/, last_index + 1)
      end
      return total
    end

    def replace_soa_ttl_fields(line)
      #  Replace any fields which evaluate to 0
      split = line.split
      4.times {|i|
        x = i + 7
        split[x].strip!
        split[x] = get_ttl(split[x]).to_s
      }
      return split.join(" ") + "\n"
    end

    #  This method is included only for OpenDNSSEC support. It should not be
    #  used otherwise.
    #  Frig the RR type so that NSEC records appear last in the RRSets.
    #  Also make sure that DNSKEYs come first (so we have a key to verify
    #  the RRSet with!).
    def prefix_for_rrset_order(type, type_was) # :nodoc: all
      #  Now make sure that NSEC(3) RRs go to the back of the list
      if ['NSEC', 'NSEC3'].include?type.string
        if (type_was == Types::RRSIG)
          #  Get the RRSIG first
          type_string = "ZZ" + type.string
        else
          type_string = "ZZZ" + type.string
        end
      elsif type == Types::DNSKEY
        type_string = "0" + type.string
      elsif type == Types::NS
        #  Make sure that we see the NS records first so we know the delegation status
        type_string = "1" + type.string
      else
        type_string = type.string
      end
      return type_string
    end

  end
end
