#
# Standard Library
#

require 'csv'


# Creates {Metasploit::Credential::Core} objects and their associated {Metasploit::Credential::Public},
# {Metasploit::Credential::Private}, and {Metasploit::Credential::Realm} objects from a CSV file.
#
# Successful import will also create a {Metasploit::Credential::Origin::Import}
class Metasploit::Credential::Importer::Core
  include Metasploit::Credential::Importer::Base
  include Metasploit::Credential::Creation

  #
  # Constants
  #

  # This token represents an explict Blank entry. An empty field instead indicates that we do not know what this value is
  BLANK_TOKEN = "<BLANK>"

  # Valid headers for a CSV containing heterogenous {Metasploit::Credential::Private} types and values for {Metasploit::Credential::Realm}
  VALID_LONG_CSV_HEADERS = [:username, :private_type, :private_data,
                            :realm_key, :realm_value, :host_address,
                            :service_port, :service_name,
                            :service_protocol, :status, :access_level,
                            :last_attempted_at
  ]

  # Valid headers for a "short" CSV containing only data for {Metasploit::Credential::Public} and {Metasploit::Credential::Private} objects
  VALID_SHORT_CSV_HEADERS = [:username,  :private_data]

  #
  # Attributes
  #

  # @!attribute csv_object
  #   The `CSV` instance created from `#input`
  #   @return [CSV]
  attr_reader :csv_object



  # @!attribute private_credential_type
  #   The name of one of the subclasses of {Metasploit::Credential::Private}.  This will be the same for all the
  #   {Metasploit::Credential::Private} objects created during the import.
  #   @return [String]
  attr_accessor :private_credential_type


  #
  # Method Validations
  #
  validate :header_format_and_csv_wellformedness

  # Ensure that {#private_credential_type} refers to a class that is allowed to be imported by this importer
  validate :private_type_is_allowed, if: Proc.new{ |i| i.private_credential_type.present? }


  #
  # Instance Methods
  #

  # An instance of `CSV` from whence cometh the sweet sweet credential input
  #
  # @return [CSV]
  def csv_object
    @csv_object ||= CSV.new(input, headers:true, return_headers: true)
  end


  # The key data inside the file at +key_file_name+
  # @param key_file_name [String]
  # @return [String]
  def key_data_from_file(key_file_name)
    full_key_file_path = File.join(File.dirname(input.path), Metasploit::Credential::Importer::Zip::KEYS_SUBDIRECTORY_NAME, key_file_name)
    File.open(full_key_file_path, 'r').read
  end

  # If no {#private_credential_type} is set, assumes that the CSV contains a mixture of private types and realms.
  # Otherwise, assume that this is a short form import and process accordingly.
  # @return [void]
  def import!
    if csv_object.first.headers.include? 'private_type'
      result =  import_long_form
    else
      result =  import_short_form
    end
    return result
  end

  # Performs an import of a "long" CSV - one that that contains realms and heterogenous private types
  # Performs a pretty naive import from the data in {#csv_object}, allowing the import to have different private types
  # per row, and attempting to reduce database lookups by storing found or created {Metasploit::Credential::Realm}
  # objects in a lookup Hash that gets updated with every new Realm found, and then consulted in analysis of subsequent
  # rows.
  #
  # @return [void]
  def import_long_form
    all_creds_valid = true
    realms = Hash.new
    Metasploit::Credential::Core.transaction do
      core_opts = []
      rows = []
      csv_object.each do |row|

        next if row.header_row?
        next unless row['username'].present? || row['private_data'].present?

        username      = row['username'].present? ? row['username'] : ''

        realm_key     = row['realm_key']
        realm_value   = row['realm_value']  # Use the name of the Realm as a lookup for getting the object

        private_class = row['private_type'].present? ? row['private_type'].constantize : ''
        private_data  = row['private_data'].present? ? row['private_data'] : ''


        if realms[realm_value].nil?
          realms[realm_value]  = Metasploit::Credential::Realm.where(key: realm_key, value: realm_value).first_or_create
        end

        realm_object_for_row   = realms[realm_value]

        public_object = create_public_from_field(username)

        if private_class.present? &&  LONG_FORM_ALLOWED_PRIVATE_TYPE_NAMES.include?(private_class.name)
          if private_data.strip == BLANK_TOKEN
            private_object_for_row = Metasploit::Credential::BlankPassword.first_or_create
          elsif private_class == Metasploit::Credential::SSHKey
            private_object_for_row = Metasploit::Credential::SSHKey.where(data: key_data_from_file(private_data)).first_or_create
          else
            private_object_for_row = private_class.where(data: private_data).first_or_create
          end
        end
        all_creds_valid = all_creds_valid && public_object && private_object_for_row && (public_object.valid? && private_object_for_row.valid?)

        core_opts << {origin:origin, workspace_id: workspace.id,
         public: public_object,
         private: private_object_for_row,
         realm: realm_object_for_row}

        rows << row



      end
      if all_creds_valid
        core_opts.each_index do |index|
          row = rows[index]


          # Host and Service information for Logins
          host_address      = row['host_address']
          service_port      = row['service_port']
          service_protocol  = row['service_protocol']
          service_name      = row['service_name']
          # These were not initially included in the export, so handle
          # legacy cases:
          access_level      = row['access_level'].present? ? row['access_level'] : ''
          last_attempted_at = row['last_attempted_at'].present? ? row['last_attempted_at'] : ''
          status            = row['status'].present? ? row['status'] : ''

          if Metasploit::Credential::Core.where(core_opts[index]).blank?
            core = create_credential_core(core_opts[index])
          else
            core = Metasploit::Credential::Core.where(core_opts[index]).first
          end


          if host_address.present? && service_port.present? && service_protocol.present?
            login_opts = {
                core: core,
                address: host_address,
                port: service_port,
                protocol: service_protocol,
                workspace_id: workspace.id,
                service_name: service_name.present? ? service_name : ""
            }
            login_opts[:last_attempted_at] = last_attempted_at unless status.blank?
            login_opts[:status]            = status unless status.blank?
            login_opts[:access_level]      = access_level unless access_level.blank?

            create_credential_login(login_opts)

          end
        end
      end
      end
    return all_creds_valid
  end


  # Performs an import of a "short" form of CSV - one that contains only one type of {Metasploit::Credential::Private}
  # and no {Metasploit::Credential::Realm} data
  # @return [Boolean]
  def import_short_form
    core_opts = []
    all_creds_valid = true
    Metasploit::Credential::Core.transaction do
      csv_object.each do |row|
        next if row.header_row?

        username     = row['username'].present? ? row['username'] : ''
        private_data  = row['private_data'].present? ? row['private_data'] : ''

        public_object = create_public_from_field(username)

        if private_data.strip == BLANK_TOKEN
          private_object_for_row = Metasploit::Credential::BlankPassword.first_or_create
        else
          private_object_for_row = @private_credential_type.constantize.where(data: row['private_data']).first_or_create
        end

        # need to check private_object_for_row.valid? to raise a user facing message if any cred had invalid private

        all_creds_valid = all_creds_valid && (public_object.valid? && private_object_for_row.valid?)


        core_opts << {origin:origin, workspace_id: workspace.id,
                                      public: public_object,
                                      private: private_object_for_row}
      end
      if all_creds_valid
        core_opts.each do |item|
          if Metasploit::Credential::Core.where(public: item[:public], private: item[:private]).blank?
            create_credential_core(item)
          end
        end
      end


    end
    return  all_creds_valid
  end


  private

  # Takes the username field and checks to see if it should be Blank or else a Username object
  #
  # @param [String] :username the username field contents
  # @return [Metasploit::Credential::Public] the Public created from the field
  def create_public_from_field(username)
    if username.strip == BLANK_TOKEN
      username = " "
    end
    create_credential_public(username: username)
  end

  # Returns true if the headers are correct, based on whether a private type has been chosen
  # @param csv_headers [Array] the headers in the CSV contained in {#input}
  # @return [Boolean]
  def csv_headers_are_correct?(csv_headers)
    if csv_headers.include? 'private_type'
      return csv_headers.map(&:to_sym) == VALID_LONG_CSV_HEADERS
    else
      return csv_headers.map(&:to_sym) == VALID_SHORT_CSV_HEADERS
    end
  end

  # Invalid if CSV is malformed, headers are not in compliance, or CSV contains no data
  #
  # @return [void]
  def header_format_and_csv_wellformedness
    begin
      if csv_object.header_row?
        csv_headers = csv_object.first.fields
        if csv_headers_are_correct?(csv_headers)
          next_row = csv_object.gets
          if next_row.present?
            csv_object.rewind
            true
          else
            errors.add(:input, :empty_csv)
          end
        else
          errors.add(:input, :incorrect_csv_headers)
        end
      else
        fail "CSV has already been accessed past index 0"
      end
    rescue ::CSV::MalformedCSVError
      errors.add(:input, :malformed_csv)
    end
  end

  # Returns true if the {#private_credential_type} is in {Metasploit::Credential::Importer::Base::ALLOWED_PRIVATE_TYPE_NAMES}
  # @return [void]
  def private_type_is_allowed
    if Metasploit::Credential::Importer::Base::SHORT_FORM_ALLOWED_PRIVATE_TYPE_NAMES.include? @private_credential_type
      true
    else
      errors.add(:private_credential_type, :invalid_type)
    end
  end
end
