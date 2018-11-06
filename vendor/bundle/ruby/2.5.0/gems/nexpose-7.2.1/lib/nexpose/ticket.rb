module Nexpose

  class Connection
    include XMLUtils

    def list_tickets
      # TODO: Should take in filters as arguments.
      xml = make_xml('TicketListingRequest')
      r   = execute(xml, '1.2')
      tickets = []
      if r.success
        r.res.elements.each('TicketListingResponse/TicketSummary') do |summary|
          tickets << TicketSummary.parse(summary)
        end
      end
      tickets
    end

    alias tickets list_tickets

    # Deletes a Nexpose ticket.
    #
    # @param [Fixnum] ticket Unique ID of the ticket to delete.
    # @return [Boolean] Whether or not the ticket deletion succeeded.
    #
    def delete_ticket(ticket)
      # TODO: Take Ticket object, too, and pull out IDs.
      delete_tickets([ticket])
    end

    # Deletes a Nexpose ticket.
    #
    # @param [Array[Fixnum]] tickets Array of unique IDs of tickets to delete.
    # @return [Boolean] Whether or not the ticket deletions succeeded.
    #
    def delete_tickets(tickets)
      # TODO: Take Ticket objects, too, and pull out IDs.
      xml = make_xml('TicketDeleteRequest')
      tickets.each do |id|
        xml.add_element('Ticket', { 'id' => id })
      end

      (execute xml, '1.2').success
    end
  end

  # Summary of ticket information returned from a ticket listing request.
  # For more details, issue a ticket detail request.
  #
  class TicketSummary

    # The ID number of the ticket.
    attr_accessor :id

    # Ticket name.
    attr_accessor :name

    # The asset the ticket is created for.
    attr_accessor :asset_id
    alias device_id asset_id
    alias device_id= asset_id=

    # The login name of person to whom the ticket is assigned.
    # The user must have view asset privilege on the asset specified in the asset-id attribute.
    attr_accessor :assigned_to

    # The relative priority of the ticket, assigned by the creator of the ticket.
    # @see Nexpose::Ticket::Priority
    attr_accessor :priority

    # The login name of the person who created the ticket.
    attr_accessor :author

    # Date and time of ticket creation.
    attr_accessor :created_on

    # The current status of the ticket.
    attr_accessor :state

    def initialize(name, id)
      @id   = id
      @name = name
    end

    def self.parse(xml)
      ticket              = new(xml.attributes['name'], xml.attributes['id'].to_i)
      ticket.asset_id     = xml.attributes['device-id'].to_i
      ticket.assigned_to  = xml.attributes['assigned-to']
      lookup              = Ticket::Priority.constants.reduce({}) { |a, e| a[Ticket::Priority.const_get(e)] = e; a }
      ticket.priority     = lookup[xml.attributes['priority']]
      ticket.author       = xml.attributes['author']
      ticket.created_on   = DateTime.parse(xml.attributes['created-on']).to_time
      ticket.created_on -= ticket.created_on.gmt_offset
      lookup              = Ticket::State.constants.reduce({}) { |a, e| a[Ticket::State.const_get(e)] = e; a }
      ticket.state        = lookup[xml.attributes['state']]
      ticket
    end

    module State
      OPEN             = 'O'
      ASSIGNED         = 'A'
      MODIFIED         = 'M'
      FIXED            = 'X'
      PARTIAL          = 'P'
      REJECTED_FIX     = 'R'
      PRIORITIZED      = 'Z'
      NOT_REPRODUCIBLE = 'F'
      NOT_ISSUE        = 'I'
      CLOSED           = 'C'
      UNKNOWN          = 'U'
    end

    module Priority
      LOW      = 'low'
      MODERATE = 'moderate'
      NORMAL   = 'normal'
      HIGH     = 'high'
      CRITICAL = 'critical'
    end
  end

  class Ticket < TicketSummary

    # List of vulnerabilities (by ID) this ticket addresses.
    attr_accessor :vulnerabilities

    # Array of comments about the ticket.
    attr_accessor :comments

    # History of events on this ticket.
    attr_accessor :history

    def initialize(name, id = nil)
      @id              = id
      @name            = name
      @priority        = Priority::NORMAL
      @vulnerabilities = []
      @comments        = []
      @history         = []
    end

    # Save this ticket to a Nexpose console.
    #
    # @param [Connection] connection Connection to console where ticket exists.
    # @return [Fixnum] Unique ticket ID assigned to this ticket.
    #
    def save(connection)
      xml = connection.make_xml('TicketCreateRequest')
      xml.add_element(to_xml)

      response = connection.execute(xml, '1.2')
      @id = response.attributes['id'].to_i if response.success
    end

    # Delete this ticket from the system.
    #
    # @param [Connection] connection Connection to console where ticket exists.
    # @return [Boolean] Whether the ticket was successfully delete.
    #
    def delete(connection)
      connection.delete_ticket(@id)
    end

    # Load existing ticket data.
    #
    # @param [Connection] connection Connection to console where ticket exists.
    # @param [Fixnum] id Ticket ID of an existing ticket.
    # @return [Ticket] Ticket populated with current state.
    #
    def self.load(connection, id)
      # TODO: Load multiple tickets in a single request, as supported by API.
      xml = connection.make_xml('TicketDetailsRequest')
      xml.add_element('Ticket', { 'id' => id })
      response = connection.execute(xml, '1.2')
      response.res.elements.each('//TicketInfo') do |info|
        return parse_details(info)
      end
    end

    def to_xml
      xml = REXML::Element.new('TicketCreate')
      xml.add_attributes({ 'name' => @name,
                           'priority' => @priority,
                           'device-id' => @asset_id,
                           'assigned-to' => @assigned_to })

      vuln_xml = REXML::Element.new('Vulnerabilities')
      @vulnerabilities.each do |vuln_id|
        vuln_xml.add_element('Vulnerability', { 'id' => vuln_id.downcase })
      end
      xml.add_element(vuln_xml)

      unless @comments.empty?
        comments_xml = REXML::Element.new('Comments')
        @comments.each do |comment|
          comment_xml = REXML::Element.new('Comment')
          comment_xml.add_text(comment)
          comments_xml.add_element(comment_xml)
        end
        xml.add_element(comments_xml)
      end

      xml
    end

    def self.parse_details(xml)
      ticket = parse(xml)

      xml.elements.each('Vulnerabilities/Vulnerability') do |vuln|
        ticket.vulnerabilities << vuln.attributes['id']
      end

      xml.elements.each('TicketHistory/Entry') do |entry|
        ticket.history << Event.parse(entry)
      end

      ticket.comments = ticket.history.select { |h| h.description == 'Added comment' }.map(&:comment)

      ticket
    end

    class Event

      # Date and time of the ticket event.
      attr_reader :created_on
      # The login name of the person responsible for the event.
      attr_reader :author
      # The status of the ticket at the time the event was recorded.
      attr_reader :state
      # Description of the ticket event.
      attr_accessor :description
      # Comment on the ticket event.
      attr_accessor :comment

      def initialize(state, author, created)
        @state   = state
        @author  = author
        @created = created
      end

      def self.parse(xml)
        author        = xml.attributes['author']
        created_on    = DateTime.parse(xml.attributes['created-on']).to_time
        created_on -= created_on.gmt_offset

        event         = REXML::XPath.first(xml, 'Event')
        lookup        = Ticket::State.constants.reduce({}) { |a, e| a[Ticket::State.const_get(e)] = e; a }
        state         = lookup[event.attributes['state']]
        desc          = event.text

        event         = new(state, author, created_on)

        comment       = REXML::XPath.first(xml, 'Comment')
        event.comment = comment.text if comment

        event.description = desc if desc
        event
      end
    end
  end
end
