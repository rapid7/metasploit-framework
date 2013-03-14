# encoding: utf-8
module Mail
  class Address
    
    include Mail::Utilities
    
    # Mail::Address handles all email addresses in Mail.  It takes an email address string
    # and parses it, breaking it down into it's component parts and allowing you to get the
    # address, comments, display name, name, local part, domain part and fully formatted
    # address.
    # 
    # Mail::Address requires a correctly formatted email address per RFC2822 or RFC822.  It
    # handles all obsolete versions including obsolete domain routing on the local part.
    # 
    #  a = Address.new('Mikel Lindsaar (My email address) <mikel@test.lindsaar.net>')
    #  a.format       #=> 'Mikel Lindsaar <mikel@test.lindsaar.net> (My email address)'
    #  a.address      #=> 'mikel@test.lindsaar.net'
    #  a.display_name #=> 'Mikel Lindsaar'
    #  a.local        #=> 'mikel'
    #  a.domain       #=> 'test.lindsaar.net'
    #  a.comments     #=> ['My email address']
    #  a.to_s         #=> 'Mikel Lindsaar <mikel@test.lindsaar.net> (My email address)'
    def initialize(value = nil)
      @output_type = nil
      @tree = nil
      @raw_text = value
      case
      when value.nil?
        @parsed = false
        return
      else
        parse(value)
      end
    end
    
    # Returns the raw imput of the passed in string, this is before it is passed
    # by the parser.
    def raw
      @raw_text
    end

    # Returns a correctly formatted address for the email going out.  If given
    # an incorrectly formatted address as input, Mail::Address will do it's best
    # to format it correctly.  This includes quoting display names as needed and
    # putting the address in angle brackets etc.
    #
    #  a = Address.new('Mikel Lindsaar (My email address) <mikel@test.lindsaar.net>')
    #  a.format #=> 'Mikel Lindsaar <mikel@test.lindsaar.net> (My email address)'
    def format
      parse unless @parsed
      case
      when tree.nil?
        ''
      when display_name
        [quote_phrase(display_name), "<#{address}>", format_comments].compact.join(" ")
      else
        [address, format_comments].compact.join(" ")
      end
    end

    # Returns the address that is in the address itself.  That is, the 
    # local@domain string, without any angle brackets or the like.
    # 
    #  a = Address.new('Mikel Lindsaar (My email address) <mikel@test.lindsaar.net>')
    #  a.address #=> 'mikel@test.lindsaar.net'
    def address
      parse unless @parsed
      domain ? "#{local}@#{domain}" : local
    end
    
    # Provides a way to assign an address to an already made Mail::Address object.
    # 
    #  a = Address.new
    #  a.address = 'Mikel Lindsaar (My email address) <mikel@test.lindsaar.net>'
    #  a.address #=> 'mikel@test.lindsaar.net'
    def address=(value)
      parse(value)
    end
    
    # Returns the display name of the email address passed in.
    # 
    #  a = Address.new('Mikel Lindsaar (My email address) <mikel@test.lindsaar.net>')
    #  a.display_name #=> 'Mikel Lindsaar'
    def display_name
      parse unless @parsed
      @display_name ||= get_display_name
      Encodings.decode_encode(@display_name.to_s, @output_type) if @display_name
    end
    
    # Provides a way to assign a display name to an already made Mail::Address object.
    # 
    #  a = Address.new
    #  a.address = 'mikel@test.lindsaar.net'
    #  a.display_name = 'Mikel Lindsaar'
    #  a.format #=> 'Mikel Lindsaar <mikel@test.lindsaar.net>'
    def display_name=( str )
      @display_name = str
    end

    # Returns the local part (the left hand side of the @ sign in the email address) of
    # the address
    # 
    #  a = Address.new('Mikel Lindsaar (My email address) <mikel@test.lindsaar.net>')
    #  a.local #=> 'mikel'
    def local
      parse unless @parsed
      "#{obs_domain_list}#{get_local.strip}" if get_local
    end

    # Returns the domain part (the right hand side of the @ sign in the email address) of
    # the address
    # 
    #  a = Address.new('Mikel Lindsaar (My email address) <mikel@test.lindsaar.net>')
    #  a.domain #=> 'test.lindsaar.net'
    def domain
      parse unless @parsed
      strip_all_comments(get_domain) if get_domain
    end
    
    # Returns an array of comments that are in the email, or an empty array if there
    # are no comments
    # 
    #  a = Address.new('Mikel Lindsaar (My email address) <mikel@test.lindsaar.net>')
    #  a.comments #=> ['My email address']
    def comments
      parse unless @parsed
      if get_comments.empty?
        nil
      else
        get_comments.map { |c| c.squeeze(" ") }
      end
    end
    
    # Sometimes an address will not have a display name, but might have the name
    # as a comment field after the address.  This returns that name if it exists.
    # 
    #  a = Address.new('mikel@test.lindsaar.net (Mikel Lindsaar)')
    #  a.name #=> 'Mikel Lindsaar'
    def name
      parse unless @parsed
      get_name
    end
    
    # Returns the format of the address, or returns nothing
    # 
    #  a = Address.new('Mikel Lindsaar (My email address) <mikel@test.lindsaar.net>')
    #  a.format #=> 'Mikel Lindsaar <mikel@test.lindsaar.net> (My email address)'
    def to_s
      parse unless @parsed
      format
    end
    
    # Shows the Address object basic details, including the Address
    #  a = Address.new('Mikel (My email) <mikel@test.lindsaar.net>')
    #  a.inspect #=> "#<Mail::Address:14184910 Address: |Mikel <mikel@test.lindsaar.net> (My email)| >"
    def inspect
      parse unless @parsed
      "#<#{self.class}:#{self.object_id} Address: |#{to_s}| >"
    end
    
    def encoded
      @output_type = :encode
      format
    end
    
    def decoded
      @output_type = :decode
      format
    end

    private
    
    def parse(value = nil)
      @parsed = true
      case
      when value.nil?
        nil
      when value.class == String
        self.tree = Mail::AddressList.new(value).address_nodes.first
      else
        self.tree = value
      end
    end
    
    
    def get_domain
      if tree.respond_to?(:angle_addr) && tree.angle_addr.respond_to?(:addr_spec) && tree.angle_addr.addr_spec.respond_to?(:domain)
        @domain_text ||= tree.angle_addr.addr_spec.domain.text_value.strip
      elsif tree.respond_to?(:domain)
        @domain_text ||= tree.domain.text_value.strip
      elsif tree.respond_to?(:addr_spec) && tree.addr_spec.respond_to?(:domain)
        tree.addr_spec.domain.text_value.strip
      else
        nil
      end
    end

    def strip_all_comments(string)
      unless comments.blank?
        comments.each do |comment|
          string = string.gsub("(#{comment})", '')
        end
      end
      string.strip
    end

    def strip_domain_comments(value)
      unless comments.blank?
        comments.each do |comment|
          if get_domain && get_domain.include?("(#{comment})")
            value = value.gsub("(#{comment})", '')
          end
        end
      end
      value.to_s.strip
    end
    
    def get_comments
      if tree.respond_to?(:comments)
        @comments = tree.comments.map { |c| unparen(c.text_value.to_str) } 
      else
        @comments = []
      end
    end
    
    def get_display_name
      if tree.respond_to?(:display_name)
        name = unquote(tree.display_name.text_value.strip)
        str = strip_all_comments(name.to_s)
      elsif comments
        if domain
          str = strip_domain_comments(format_comments)
        else
          str = nil
        end
      else
        nil
      end
      
      if str.blank?
        nil
      else
        str
      end
    end
    
    def get_name
      if display_name
        str = display_name
      else
        if comments
          comment_text = comments.join(' ').squeeze(" ")
          str = "(#{comment_text})"
        end
      end

      if str.blank?
        nil
      else
        unparen(str)
      end
    end
    
    # Provides access to the Treetop parse tree for this address
    def tree
      @tree
    end
    
    def tree=(value)
      @tree = value
    end
    
    def format_comments
      if comments
        comment_text = comments.map {|c| escape_paren(c) }.join(' ').squeeze(" ")
        @format_comments ||= "(#{comment_text})"
      else
        nil
      end
    end
   
    def obs_domain_list
      if tree.respond_to?(:angle_addr)
        obs = tree.angle_addr.elements.select { |e| e.respond_to?(:obs_domain_list) }
        !obs.empty? ? obs.first.text_value : nil
      else
        nil
      end
    end
    
    def get_local
      case
      when tree.respond_to?(:local_dot_atom_text)
        tree.local_dot_atom_text.text_value
      when tree.respond_to?(:angle_addr) && tree.angle_addr.respond_to?(:addr_spec) && tree.angle_addr.addr_spec.respond_to?(:local_part)
        tree.angle_addr.addr_spec.local_part.text_value
      when tree.respond_to?(:addr_spec) && tree.addr_spec.respond_to?(:local_part)
        tree.addr_spec.local_part.text_value
      else
        tree && tree.respond_to?(:local_part) ? tree.local_part.text_value : nil
      end
    end
    
 
  end
end