# --
# Copyright 2007 Nominet UK
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
module Dnsruby
  # Dnsruby::Update is a subclass of Dnsruby::Packet,
  # to be used for making DNS dynamic updates.  Programmers
  # should refer to RFC 2136 for the semantics of dynamic updates.

  # The first example below shows a complete program; subsequent examples
  # show only the creation of the update packet.
  #
  # == Add a new host
  #
  #  require 'Dnsruby'
  #
  #  # Create the update packet.
  #  update = Dnsruby::Update.new('example.com')
  #
  #  # Prerequisite is that no A records exist for the name.
  #  update.absent('foo.example.com.', 'A')
  #
  #  # Add two A records for the name.
  #  update.add('foo.example.com.', 'A', 86400, '192.168.1.2')
  #  update.add('foo.example.com.', 'A', 86400, '172.16.3.4')
  #
  #  # Send the update to the zone's primary master.
  #  res = Dnsruby::Resolver.new({:nameserver => 'primary-master.example.com'})
  #
  #  begin
  #      reply = res.send_message(update)
  #      print "Update succeeded\n"
  #   rescue Exception => e
  #      print 'Update failed: #{e}\n'
  #   end
  #
  # == Add an MX record for a name that already exists
  #
  #     update = Dnsruby::Update.new('example.com')
  #     update.present('example.com')
  #     update.add('example.com', Dnsruby::Types.MX, 86400, 10, 'mailhost.example.com')
  #
  # == Add a TXT record for a name that doesn't exist
  #
  #     update = Dnsruby::Update.new('example.com')
  #     update.absent('info.example.com')
  #     update.add('info.example.com', Types.TXT, 86400, "yabba dabba doo"')
  #
  # == Delete all A records for a name
  #
  #     update = Dnsruby::Update.new('example.com')
  #     update.present('foo.example.com', 'A')
  #     update.delete('foo.example.com', 'A')
  #
  # == Delete all RRs for a name
  #
  #     update = Dnsruby::Update.new('example.com')
  #     update.present('byebye.example.com')
  #     update.delete('byebye.example.com')
  #
  # == Perform a signed update
  #
  #     key_name = 'tsig-key'
  #     key      = 'awwLOtRfpGE+rRKF2+DEiw=='
  #
  #     update = Dnsruby::Update.new('example.com')
  #     update.add('foo.example.com', 'A', 86400, '10.1.2.3'))
  #     update.add('bar.example.com', 'A', 86400, '10.4.5.6'))
  #     res.tsig=(key_name,key)
  #
  class Update < Message
    # Returns a Dnsruby::Update object suitable for performing a DNS
    # dynamic update.  Specifically, it creates a message with the header
    # opcode set to UPDATE and the zone record type to SOA (per RFC 2136,
    # Section 2.3).
    #
    # Programs must use the push method to add RRs to the prerequisite,
    # update, and additional sections before performing the update.
    #
    # Arguments are the zone name and the class.  If the zone is omitted,
    # the default domain will be taken from the resolver configuration.
    # If the class is omitted, it defaults to IN.
    #     packet = Dnsruby::Update.new
    #     packet = Dnsruby::Update.new('example.com')
    #     packet = Dnsruby::Update.new('example.com', 'HS')
    #
    def initialize(zone=nil, klass=nil)

      #  sort out the zone section (RFC2136, section 2.3)
      if (zone==nil)
        config = Config.new
        zone = (config.search)[0]
        return unless zone
      end

      type  = 'SOA'
      klass  ||= 'IN'

      super(zone, type, klass) || return

      @header.opcode=('UPDATE')
      @header.rd=(0)
      @do_validation = false
    end

    # Ways to create the prerequisite records (exists, notexists, inuse, etc. - RFC2136, section 2.4)
    #
    #       (1)  RRset exists (value independent).  At least one RR with a
    #            specified NAME and TYPE (in the zone and class specified by
    #            the Zone Section) must exist.
    #
    #            update.present(name, type)
    #
    #       (2)  RRset exists (value dependent).  A set of RRs with a
    #            specified NAME and TYPE exists and has the same members
    #            with the same RDATAs as the RRset specified here in this
    #            Section.
    #
    #            update.present(name, type, rdata)
    #
    #       (4)  Name is in use.  At least one RR with a specified NAME (in
    #            the zone and class specified by the Zone Section) must exist.
    #            Note that this prerequisite is NOT satisfied by empty
    #            nonterminals.
    #
    #            update.present(name)
    def present(*args)
      ttl = 0
      rdata = ""
      klass = Classes.ANY
      if (args.length>=1) # domain (RFC2136, Section 2.4.4)
        name = args[0]
        type = Types.ANY
        if (args.length>=2) # RRSET (RFC2136, Section 2.4.1)
          type = args[1]
        end
        if (args.length > 2) # RRSET (RFC2136, Section 2.4.2)
          klass = Classes.new(zone()[0].zclass)
          rdata=args[2]
        end
        rec = RR.create("#{name} #{ttl} #{klass} #{type} #{rdata}")
        add_pre(rec)
        return rec
      else
        raise ArgumentError.new("Wrong number of arguments (#{args.length} for 1 or 2) for Update#present")
      end
    end

    # Ways to create the prerequisite records (exists, notexists, inuse, etc. - RFC2136, section 2.4)
    # Can be called with one arg :
    #
    #    update.absent(name)
    #       (5)  Name is not in use.  No RR of any type is owned by a
    #            specified NAME.  Note that this prerequisite IS satisfied by
    #            empty nonterminals.
    #
    # Or with two :
    #
    #    update.absent(name, type)
    #       (3)  RRset does not exist.  No RRs with a specified NAME and TYPE
    #           (in the zone and class denoted by the Zone Section) can exist.
    #
    def absent(*args)
      ttl = 0
      rdata = ""
      klass = Classes.NONE
      if (args.length>=1) # domain (RFC2136, Section 2.4.5)
        name = args[0]
        type = Types.ANY
        if (args.length==2) # RRSET (RFC2136, Section 2.4.3)
          type = args[1]
        end
        rec = RR.create("#{name} #{ttl} #{klass} #{type} #{rdata}")
        add_pre(rec)
        return rec
      else
        raise ArgumentError.new("Wrong number of arguments (#{args.length} for 1 or 2) for Update#absent")
      end
    end

    # Ways to create the update records (add, delete, RFC2136, section 2.5)
    #   " 2.5.1 - Add To An RRset
    #
    #    RRs are added to the Update Section whose NAME, TYPE, TTL, RDLENGTH
    #    and RDATA are those being added, and CLASS is the same as the zone
    #    class.  Any duplicate RRs will be silently ignored by the primary
    #    master."
    #
    #    update.add(rr)
    #    update.add([rr1, rr2])
    #    update.add(name, type, ttl, rdata)
    #
    def add(*args)
      zoneclass=zone()[0].zclass
      case args[0]
      when Array
        args[0].each do |resource|
          add(resource)
        end
      when RR
        #  Make sure that the Class is the same as the zone
        resource = args[0]
        if (resource.klass != zoneclass)
          raise ArgumentError.new("Wrong class #{resource.klass} for update (should be #{zoneclass})!")
        end
        add_update(resource)
        return resource
      else
        name=args[0]
        type=args[1]
        ttl=args[2]
        rdata=args[3]
        resource = nil
        if (Types.new(type) == Types.TXT)
          instring = "#{name} #{ttl} #{zoneclass} #{type} ";
          if (String === rdata)
            instring += " '#{rdata}'"
          elsif (Array === rdata)
            rdata.length.times {|rcounter|
            instring += " '#{rdata[rcounter]}' "
            }
          else
            instring += rdata
          end
          resource = RR.create(instring)
        else
          resource = RR.create("#{name} #{ttl} #{zoneclass} #{type} #{rdata}")
        end
        add_update(resource)
        return resource
      end
      #  @TODO@ Should be able to take RRSet!
    end

    # Ways to create the update records (add, delete, RFC2136, section 2.5)
    #
    # 2.5.2 - Delete An RRset
    #    update.delete(name, type)
    #
    #
    # 2.5.3 - Delete All RRsets From A Name
    #    update.delete(name)
    #
    # 2.5.4 - Delete An RR From An RRset
    #   update.delete(name, type, rdata)
    #
    def delete(*args)
      ttl = 0
      klass = Classes.ANY
      rdata=""
      resource = nil
      case args.length
      when 1 # name
        resource = RR.create("#{args[0]} #{ttl} #{klass} #{Types.ANY} #{rdata}")
        add_update(resource)
      when 2 # name, type
        resource = RR.create("#{args[0]} #{ttl} #{klass} #{args[1]} #{rdata}")
        add_update(resource)
      when 3 # name, type, rdata
        name = args[0]
        type = args[1]
        rdata = args[2]
        if (Types.new(type) == Types.TXT)
          instring = "#{name} #{ttl} IN #{type} ";
          if (String === rdata)
            instring += " '#{rdata}'"
          elsif (Array === rdata)
            rdata.length.times {|rcounter|
            instring += " '#{rdata[rcounter]}' "
            }
          else
            instring += rdata
          end
          resource = RR.create(instring)
        else
          resource = RR.create("#{name} #{ttl} IN #{type} #{rdata}")
        end
        resource.klass = Classes.NONE
        add_update(resource)
      end
      return resource
    end
  end
end
