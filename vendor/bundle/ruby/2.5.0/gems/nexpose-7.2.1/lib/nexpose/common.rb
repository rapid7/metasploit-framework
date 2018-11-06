module Nexpose
  # Constants useful across the Nexpose module.
  module Scope
    GLOBAL = 'global'
    SILO   = 'silo'
  end

  # Configuration structure for e-mail notification.
  #
  # The send_as and send_to_acl_as attributes are optional, but one of them is
  # required for sending reports via e-mail. The send_as attribute is required
  # for sending e-mails to users who are not on the report access list.
  # The send_to_acl attribute is required for sending e-mails to report access
  # list members.
  #
  # E-mails and attachments are sent via the Internet in clear text and are not
  # encrypted. If you do not set a valid value for either attribute,
  # the application will save the report but not send it via e-mail.
  # If you set a valid value for the send_as attribute but not for the
  # send_to_acl_as attribute, the application will send the report via e-mail to
  # non-access-list members only. If you set a valid value for the
  # send_to_acl_as attribute, the application will send the report via e-mail to
  # access-list members only. If you set a valid value for both attributes,
  # the application will send reports via e-mail to access-list members and
  # non-members.
  class Email
    # Send as file attachment or zipped file to individuals who are not members
    # of the report access list.
    # [String] Attachment format, 'file' | 'zip'.
    attr_accessor :send_as
    # Send to all the authorized users of sites, groups, and assets.
    # [Fixnum] 1 | 0
    attr_accessor :to_all_authorized
    # Send to users on the report access list.
    # [String] Attachment format 'file' | 'zip'
    attr_accessor :send_to_acl_as
    # Format to send to users on the report access list.
    # [String] Attachment format 'file' | 'zip' | 'url'
    attr_accessor :send_to_owner_as
    # Sender that e-mail will be attributed to.
    # [String] an email address
    attr_accessor :sender
    # SMTP relay server.
    # [String] the IP address, host name or FQDN of the SMTP server.
    attr_accessor :smtp_relay_server
    # Recipients will be in form of email address.
    # [Array<String>] E-mail addresses of additional report recipients (i.e., not already on the report access list).
    attr_accessor :recipients

    def initialize(to_all_authorized, send_to_owner_as, send_to_acl_as, send_as)
      @to_all_authorized = to_all_authorized
      @send_to_owner_as  = send_to_owner_as
      @send_to_acl_as    = send_to_acl_as
      @send_as           = send_as
      @recipients        = []
    end

    def to_xml
      xml = '<Email'
      xml << %( toAllAuthorized='#{@to_all_authorized ? 1 : 0}')
      xml << %( sendToOwnerAs='#{@send_to_owner_as}') if @send_to_owner_as
      xml << %( sendToAclAs='#{@send_to_acl_as}') if @send_to_acl_as
      xml << %( sendAs='#{@send_as}') if @send_as
      xml << '>'
      xml << %(<Sender>#{@sender}</Sender>) if @sender
      xml << %(<SmtpRelayServer>#{@smtp_relay_server}</SmtpRelayServer>) if @smtp_relay_server
      if @recipients
        xml << '<Recipients>'
        @recipients.each do |recipient|
          xml << %(<Recipient>#{recipient}</Recipient>)
        end
        xml << '</Recipients>'
      end
      xml << '</Email>'
    end

    def self.parse(xml)
      xml.elements.each('//Email') do |email|
        config = Email.new(email.attributes['toAllAuthorized'] == '1',
                           email.attributes['sendToOwnerAs'],
                           email.attributes['sendToAclAs'],
                           email.attributes['sendAs'])

        xml.elements.each('//Sender') do |sender|
          config.sender = sender.text
        end
        xml.elements.each('//SmtpRelayServer') do |server|
          config.smtp_relay_server = server.text
        end
        xml.elements.each('//Recipient') do |recipient|
          config.recipients << recipient.text
        end
        return config
      end
      nil
    end
  end

  # Configuration structure for ad-hoc schedules
  class AdHocSchedule < APIObject
    # Start time in ISO8601 format
    attr_accessor :start

    # The template to use to scan the assets
    attr_accessor :scan_template_id

    # The amount of time, in minutes, to allow execution before stopping.
    attr_accessor :max_duration

    def initialize(start, scan_template_id, max_duration = nil)
      @start = start
      @scan_template_id = scan_template_id
      @max_duration = max_duration if max_duration
    end

    def as_xml
      xml = REXML::Element.new('AdHocSchedule')
      xml.attributes['start']       = @start
      xml.attributes['maxDuration'] = @max_duration if @max_duration
      xml.attributes['template']    = @scan_template_id
      xml
    end

    def from_hash(hash)
      schedule = AdHocSchedule.new(hash[:start], hash[:scan_template_id])
      schedule.max_duration = hash[:max_duration] if hash[:max_duration]
      schedule
    end

    def to_xml
      as_xml.to_s
    end
  end

  # Configuration structure for schedules.
  class Schedule < APIObject
    # Whether or not this schedule is enabled.
    attr_accessor :enabled
    # Valid schedule types: daily, hourly, monthly-date, monthly-day, weekly.
    attr_accessor :type
    # The repeat interval based upon type.
    attr_accessor :interval
    # Starting time of the scheduled scan (in ISO 8601 format).
    attr_accessor :start
    # The amount of time, in minutes, to allow execution before stopping.
    attr_accessor :max_duration
    # The date after which the schedule is disabled, in ISO 8601 format.
    attr_accessor :not_valid_after
    # Extended attributes added with the new scheduler implementation
    attr_accessor :is_extended
    attr_accessor :hour
    attr_accessor :minute
    attr_accessor :date
    attr_accessor :day
    attr_accessor :occurrence
    attr_accessor :start_month
    # Timezone in which start time run. If not set will default to console timezone.
    # If console timezone is not supported it defaults to utc.
    attr_accessor :timezone
    attr_accessor :next_run_time
    # scan-schedule attributes
    attr_accessor :repeater_type
    # Scan template to use when starting a scan job.
    attr_accessor :scan_template_id
    # Starting time of the scheduled scan (in ISO 8601 format). Relative to the console timezone
    attr_accessor :console_start
    # The timezone of the console.
    attr_accessor :console_timezone

    # @param [Time] start
    def initialize(type, interval, start, enabled = true, scan_template_id = nil)
      @type             = type
      @interval         = interval
      @start            = start
      @enabled          = enabled
      @scan_template_id = scan_template_id
    end

    def self.from_hash(hash)
      start = nil
      start = Nexpose::ISO8601.to_time(hash[:start_date]) if hash[:start_date]
      repeat_scan_hash = hash[:repeat_scan]
      if repeat_scan_hash.nil?
        schedule = new('daily', 0, start)
      else
        schedule = new(repeat_scan_hash[:type], repeat_scan_hash[:interval], start)
      end
      schedule.enabled          = hash[:enabled].nil? ? true : hash[:enabled]
      schedule.scan_template_id = hash[:scan_template_id]
      schedule.start            = Nexpose::ISO8601.to_time(hash[:start_date]) if hash[:start_date]
      schedule.max_duration     = hash[:maximum_scan_duration] if hash[:maximum_scan_duration]
      schedule.not_valid_after  = Nexpose::ISO8601.to_time(hash[:not_valid_after_date]) if hash[:not_valid_after_date]
      schedule.timezone         = hash[:time_zone] if hash[:time_zone]
      schedule.next_run_time    = hash[:next_run_time] if hash[:next_run_time]
      schedule.console_start    = Nexpose::ISO8601.to_time(hash[:console_start_date]) if hash[:console_start_date]
      schedule.console_timezone = hash[:console_time_zone] if hash[:console_time_zone]

      unless repeat_scan_hash.nil?
        schedule.type          = repeat_scan_hash[:type]
        schedule.interval      = repeat_scan_hash[:interval]
        schedule.repeater_type = 'restart' if repeat_scan_hash[:on_repeat] == 'restart-scan'
        schedule.repeater_type = 'continue' if repeat_scan_hash[:on_repeat] == 'resume-scan'
        schedule.is_extended   = repeat_scan_hash[:is_extended] if repeat_scan_hash[:is_extended]
        schedule.hour          = repeat_scan_hash[:hour] if repeat_scan_hash[:hour]
        schedule.minute        = repeat_scan_hash[:minute] if repeat_scan_hash[:minute]
        schedule.date          = repeat_scan_hash[:date] if repeat_scan_hash[:date]
        schedule.day           = repeat_scan_hash[:day] if repeat_scan_hash[:day]
        schedule.occurrence    = repeat_scan_hash[:occurrence] if repeat_scan_hash[:occurrence]
        schedule.start_month   = repeat_scan_hash[:start_month] if repeat_scan_hash[:start_month]
      end

      schedule
    end

    def to_h
      schedule_hash = {
        enabled: @enabled,
        scan_template_id: @scan_template_id,
        maximum_scan_duration: @max_duration
      }
      schedule_hash[:start_date]           = Nexpose::ISO8601.to_string(@start) if @start
      schedule_hash[:not_valid_after_date] = Nexpose::ISO8601.to_string(@not_valid_after) if @not_valid_after
      schedule_hash[:time_zone]            = @timezone if @timezone

      unless (@type.nil? || @interval.to_i.zero?) && !@is_extended
        repeat_scan_hash = {
          type: @type,
          interval: @interval
        }
        repeat_scan_hash[:on_repeat] = 'restart-scan' if @repeater_type == 'restart'
        repeat_scan_hash[:on_repeat] = 'resume-scan' if @repeater_type == 'continue'
        if @is_extended
          repeat_scan_hash[:is_extended] = @is_extended
          repeat_scan_hash[:hour]        = @hour if @hour
          repeat_scan_hash[:minute]      = @minute if @minute
          repeat_scan_hash[:date]        = @date if @date
          repeat_scan_hash[:day]         = @day if @day
          repeat_scan_hash[:occurrence]  = @occurrence if @occurrence
          repeat_scan_hash[:start_month] = @start_month if @start_month
        end
        schedule_hash[:repeat_scan] = repeat_scan_hash
      end

      schedule_hash
    end

    def as_xml
      xml = REXML::Element.new('Schedule')
      xml.attributes['enabled']       = @enabled ? 1 : 0
      xml.attributes['type']          = @type
      xml.attributes['interval']      = @interval
      xml.attributes['start']         = @start if @start
      xml.attributes['maxDuration']   = @max_duration if @max_duration
      xml.attributes['notValidAfter'] = @not_valid_after if @not_valid_after
      xml.attributes['repeaterType']  = @repeater_type if @repeater_type
      xml.attributes['is_extended']   = @is_extended if @is_extended
      xml.attributes['hour']          = @hour if @hour
      xml.attributes['minute']        = @minute if @minute
      xml.attributes['date']          = @date if @date
      xml.attributes['day']           = @day if @day
      xml.attributes['occurrence']    = @occurrence if @occurrence
      xml.attributes['start_month']   = @start_month if @start_month
      xml.attributes['timezone']      = @timezone if @timezone
      xml.attributes['template']      = @scan_template_id if @scan_template_id
      xml
    end

    def to_xml
      as_xml.to_s
    end

    def self.parse(xml)
      schedule = Schedule.new(xml.attributes['type'],
                              xml.attributes['interval'].to_i,
                              xml.attributes['start'],
                              xml.attributes['enabled'] != '0')

      # Optional parameters.
      schedule.max_duration     = xml.attributes['maxDuration'].to_i if xml.attributes['maxDuration']
      schedule.not_valid_after  = xml.attributes['notValidAfter'] if xml.attributes['notValidAfter']
      schedule.repeater_type    = xml.attributes['repeaterType'] if xml.attributes['repeaterType']
      schedule.is_extended      = xml.attributes['is_extended'] if xml.attributes['is_extended']
      schedule.hour             = xml.attributes['hour'] if xml.attributes['hour']
      schedule.minute           = xml.attributes['minute'] if xml.attributes['minute']
      schedule.date             = xml.attributes['date'] if xml.attributes['date']
      schedule.day              = xml.attributes['day'] if xml.attributes['day']
      schedule.occurrence       = xml.attributes['occurrence'] if xml.attributes['occurrence']
      schedule.start_month      = xml.attributes['start_month'] if xml.attributes['start_month']
      schedule.timezone         = xml.attributes['timezone'] if xml.attributes['timezone']
      schedule.next_run_time    = xml.attributes['next_run_time'] if xml.attributes['next_run_time']
      schedule.scan_template_id = xml.attributes['template'] if xml.attributes['template']
      schedule
    end

    # Recurring schedule type constants. These are all the possible values which
    # may be used to create a Schedule.
    #
    module Type
      DAILY        = 'daily'
      HOURLY       = 'hourly'
      WEEKLY       = 'weekly'
      MONTHLY_DATE = 'monthly-date'
      MONTHLY_DAY  = 'monthly-day'
    end
  end

  # Organization configuration, as used in Site and Silo.
  class Organization < APIObject
    attr_accessor :name
    attr_accessor :url
    attr_accessor :primary_contact
    attr_accessor :job_title
    attr_accessor :email
    attr_accessor :telephone
    attr_accessor :address
    attr_accessor :state
    attr_accessor :city
    attr_accessor :zip
    attr_accessor :country

    def initialize(&block)
      instance_eval(&block) if block_given?
    end

    def to_h
      { name: name,
        url: url,
        primary_contact: primary_contact,
        job_title: job_title,
        email: email,
        telephone: telephone,
        address: address,
        state: state,
        city: city,
        zip: zip,
        country: country }
    end

    # Create organization object from hash
    def self.create(hash)
      new do |org|
        org.name            = hash[:name]
        org.url             = hash[:url]
        org.primary_contact = hash[:primary_contact]
        org.job_title       = hash[:job_title]
        org.email           = hash[:email]
        org.telephone       = hash[:telephone]
        org.address         = hash[:address]
        org.state           = hash[:state]
        org.city            = hash[:city]
        org.zip             = hash[:zip]
        org.country         = hash[:country]
      end
    end

    def self.parse(xml)
      new do |org|
        org.name            = xml.attributes['name']
        org.url             = xml.attributes['url']
        org.primary_contact = xml.attributes['primaryContact']
        org.job_title       = xml.attributes['jobTitle']
        org.email           = xml.attributes['email']
        org.telephone       = xml.attributes['telephone']
        org.address         = xml.attributes['businessAddress']
        org.state           = xml.attributes['state']
        org.city            = xml.attributes['city']
        org.zip             = xml.attributes['zip']
        org.country         = xml.attributes['country']
      end
    end

    def as_xml
      xml = REXML::Element.new('Organization')
      xml.add_attribute('name', @name)
      xml.add_attribute('url', @url)
      xml.add_attribute('primaryContact', @primary_contact)
      xml.add_attribute('jobTitle', @job_title)
      xml.add_attribute('email', @email)
      xml.add_attribute('telephone', @telephone)
      xml.add_attribute('businessAddress', @address)
      xml.add_attribute('state', @state)
      xml.add_attribute('city', @city)
      xml.add_attribute('zip', @zip)
      xml.add_attribute('country', @country)
      xml
    end
  end
end
