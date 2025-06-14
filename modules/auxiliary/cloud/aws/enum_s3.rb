##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'aws-sdk-s3'

class MetasploitModule < Msf::Auxiliary
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Amazon Web Services S3 instance enumeration',
        'Description' => %q{
          Provided AWS credentials, this module will call the authenticated
          API of Amazon Web Services to list all S3 buckets associated
          with the account
        },
        'Author' => ['Aaron Soto <aaron.soto@rapid7.com>'],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('REGION', [false, 'AWS Region (eg. "us-west-2")']),
        OptString.new('ACCESS_KEY_ID', [true, 'AWS Access Key ID (eg. "AKIAXXXXXXXXXXXXXXXX")', '']),
        OptString.new('SECRET_ACCESS_KEY', [true, 'AWS Secret Access Key (eg. "CA1+XXXXXXXXXXXXXXXXXXXXXX6aYDHHCBuLuV79")', ''])
      ]
    )
  end

  def handle_aws_errors(error)
    if error.class.module_parents.include?(Aws)
      fail_with(Failure::UnexpectedReply, error.message)
    else
      raise error
    end
  end

  def describe_s3_bucket(bucket)
    print_good "  Name:           #{bucket.name}"
    print_good "  Creation Date:  #{bucket.creation_date}"
    print_good "  # of Objects:   #{@s3.list_objects_v2(bucket: bucket.name).contents.length}"
    print_good "  Region:         #{@s3.get_bucket_location(bucket: bucket.name).location_constraint}"

    begin
      print_good "  Website:        /#{@s3.get_bucket_website(bucket: bucket.name).index_document.suffix}"
    rescue Aws::S3::Errors::NoSuchWebsiteConfiguration
      print_good '  Website:        (None)'
    end

    acl = @s3.get_bucket_acl(bucket: bucket.name)
    print_good "  Owner:          #{acl.owner.display_name}"
    print_good '  Permissions:'
    acl.grants.each do |i|
      grantee = i.grantee.type == 'CanonicalUser' ? 'User' : i.grantee.type
      grantee << " '#{i.grantee.display_name}'"
      grantee << " (#{i.grantee.email_address})" unless i.grantee.email_address.nil?
      grantee << " (#{i.grantee.uri})" unless i.grantee.uri.nil?
      print_good "                  #{grantee} granted #{i.permission}"
    end
    print_status ''
  end

  def run
    region = datastore['REGION']

    @s3 = Aws::S3::Client.new(
      region: 'us-west-2', # This doesn't actually filter anything, but
      #   it's still required.  Thanks AWS.  :-(
      access_key_id: datastore['ACCESS_KEY_ID'],
      secret_access_key: datastore['SECRET_ACCESS_KEY']
    )

    buckets = @s3.list_buckets.buckets
    if buckets.empty?
      print_status 'No buckets found.'
      return
    end

    print_good "Found #{buckets.count} buckets."
    if region.nil?
      buckets.each do |bucket|
        describe_s3_bucket(bucket)
      end
    else
      print_good "Listing buckets that match REGION '#{datastore['REGION']}':"
      buckets.each do |bucket|
        if @s3.get_bucket_location(bucket: bucket.name).location_constraint.starts_with? region
          describe_s3_bucket(bucket)
        end
      end
    end
    print_status 'Done.'
  rescue StandardError => e
    handle_aws_errors(e)
  end
end
