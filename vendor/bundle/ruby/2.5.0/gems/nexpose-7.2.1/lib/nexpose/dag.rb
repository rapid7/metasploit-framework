module Nexpose

  # Dynamic Asset Group object.
  #
  class DynamicAssetGroup

    # Unique name of this group.
    attr_accessor :name
    # Search criteria that defines which assets this group will aggregate.
    attr_accessor :criteria
    # Unique identifier of this group.
    attr_accessor :id
    # Description of this asset group.
    attr_accessor :description
    # Array of user IDs who have permission to access this group.
    attr_accessor :users

    def initialize(name, criteria = nil, description = nil)
      @name, @criteria, @description = name, criteria, description
      @users = []
    end

    # Save this dynamic asset group to the Nexpose console.
    # Warning, saving this object does not set the id. It must be retrieved
    # independently.
    #
    # @param [Connection] nsc Connection to a security console.
    # @return [Boolean] Whether the group was successfully saved.
    #
    def save(nsc)
      # load includes admin users, but save will fail if they are included.
      admins = nsc.users.select { |u| u.is_admin }.map { |u| u.id }
      @users.reject! { |id| admins.member? id }
      params = @id ? { 'entityid' => @id, 'mode' => 'edit' } : { 'entityid' => false, 'mode' => false }
      uri    = AJAX.parameterize_uri('/data/assetGroup/saveAssetGroup', params)
      data   = JSON.parse(AJAX.post(nsc, uri, _to_entity_details, AJAX::CONTENT_TYPE::JSON))
      data['response'] == 'success.'
    end

    # Load in an existing Dynamic Asset Group configuration.
    #
    # @param [Connection] nsc Connection to a security console.
    # @param [Fixnum] id Unique identifier of an existing group.
    # @return [DynamicAssetGroup] Dynamic asset group configuration.
    #
    def self.load(nsc, id)
      json = JSON.parse(AJAX.get(nsc, "/data/assetGroup/loadAssetGroup?entityid=#{id}"))
      raise APIError.new(json, json['message']) if json['response'] =~ /failure/
      raise ArgumentError.new('Not a dynamic asset group.') unless json['dynamic']
      dag = new(json['name'], Criteria.parse(json['searchCriteria']), json['description'])
      dag.id = id
      dag.users = json['users']
      dag
    end

    def _to_entity_details
      obj = { 'searchCriteria' => @criteria.to_h,
              'name' => @name,
              'description' => @description.nil? ? '' : @description,
              'dynamic' => true,
              'users' => @users }
      JSON.generate(obj)
    end
  end
end
