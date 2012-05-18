# encoding: utf-8
module Mail
  class AddressList # :nodoc:
    
    # Mail::AddressList is the class that parses To, From and other address fields from
    # emails passed into Mail.
    # 
    # AddressList provides a way to query the groups and mailbox lists of the passed in
    # string.
    # 
    # It can supply all addresses in an array, or return each address as an address object.
    # 
    # Mail::AddressList requires a correctly formatted group or mailbox list per RFC2822 or
    # RFC822.  It also handles all obsolete versions in those RFCs.
    # 
    #  list = 'ada@test.lindsaar.net, My Group: mikel@test.lindsaar.net, Bob <bob@test.lindsaar.net>;'
    #  a = AddressList.new(list)
    #  a.addresses    #=> [#<Mail::Address:14943130 Address: |ada@test.lindsaar.net...
    #  a.group_names  #=> ["My Group"]
    def initialize(string)
      if string.blank?
        @address_nodes = []
        return self
      end
      parser = Mail::AddressListsParser.new
      if tree = parser.parse(string)
        @address_nodes = tree.addresses
      else
        raise Mail::Field::ParseError.new(AddressListsParser, string, parser.failure_reason)
      end
    end
    
    # Returns a list of address objects from the parsed line
    def addresses
      @addresses ||= get_addresses.map do |address_tree|
        Mail::Address.new(address_tree)
      end
    end
    
    # Returns a list of all recipient syntax trees that are not part of a group
    def individual_recipients # :nodoc:
      @individual_recipients ||= @address_nodes - group_recipients
    end
    
    # Returns a list of all recipient syntax trees that are part of a group
    def group_recipients # :nodoc:
      @group_recipients ||= @address_nodes.select { |an| an.respond_to?(:group_name) }
    end
    
    # Returns the names as an array of strings of all groups
    def group_names # :nodoc:
      group_recipients.map { |g| g.group_name.text_value }
    end
    
    # Returns a list of address syntax trees
    def address_nodes # :nodoc:
      @address_nodes
    end
    
    private
    
    def get_addresses
      (individual_recipients + group_recipients.map { |g| get_group_addresses(g) }).flatten
    end
    
    def get_group_addresses(g)
      if g.group_list.respond_to?(:addresses)
        g.group_list.addresses
      else
        []
      end
    end
  end
end
