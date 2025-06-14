# -*- coding: binary -*-

module Msf
class Post
module Windows

# Based on the research from Tim Tomes and Mark Baggett, at
# http://pauldotcom.com/2011/11/safely-dumping-hashes-from-liv.html
module ShadowCopy

  include Msf::Post::Windows::Services
  include Msf::Post::Windows::WMIC

  def initialize(info = {})
    super

    register_options([
      OptInt.new("TIMEOUT", [ true, "Timeout for WMI command in seconds", 60 ])
    ], self.class)
  end

  #
  # Get the device name for the shadow copy, which is used when accessing
  # files on the volume.
  #
  def get_vss_device(id)
    result = get_sc_param(id,'DeviceObject')
  end

  #
  # Returns a list of volume shadow copies.
  #
  def vss_list
    ids = vss_get_ids
    shadow_copies = []
    ids.each do |id|
      print_status "Getting data for Shadow Copy #{id} (This may take a minute)"
      shadow_copies << get_sc_details("\"#{id}\"")
    end
    return shadow_copies
  end

  #
  # Use WMIC to get a list of volume shadow copy IDs.
  #
  def vss_get_ids
    result = wmic_query('shadowcopy get id')
    ids = result.scan(/\{\w{8}-\w{4}-\w{4}-\w{4}-\w{12}\}/)
    return ids
  end

  #
  # Get volume shadow storage parameters.
  #
  def vss_get_storage
    storage={}
    storage['AllocatedSpace'] = vss_get_storage_param('AllocatedSpace')
    storage['MaxSpace'] = vss_get_storage_param('MaxSpace')
    storage['UsedSpace'] = vss_get_storage_param('UsedSpace')
    return storage
  end

  #
  # Get detailed information about the volume shadow copy specified by +id+
  #
  def get_sc_details(id)
    shadowcopy={}
    shadowcopy['ID'] = id
    shadowcopy['ClientAccessible'] = get_sc_param(id,'ClientAccessible')
    shadowcopy['Count'] = get_sc_param(id,'Count')
    shadowcopy['DeviceObject'] = get_sc_param(id,'DeviceObject')
    shadowcopy['Differential'] = get_sc_param(id,'Differential')
    shadowcopy['ExposedLocally'] = get_sc_param(id,'ExposedLocally')
    shadowcopy['ExposedName'] = get_sc_param(id,'ExposedName')
    shadowcopy['ExposedRemotely'] = get_sc_param(id,'ExposedRemotely')
    shadowcopy['HardwareAssisted'] = get_sc_param(id,'HardwareAssisted')
    shadowcopy['Imported'] = get_sc_param(id,'Imported')
    shadowcopy['NoAutoRelease'] = get_sc_param(id,'NoAutoRelease')
    shadowcopy['NotSurfaced'] = get_sc_param(id,'Notsurfaced')
    shadowcopy['NoWriters'] = get_sc_param(id,'NoWriters')
    shadowcopy['OriginiatingMachine'] = get_sc_param(id,'OriginatingMachine')
    shadowcopy['Persistent'] = get_sc_param(id,'Persistent')
    shadowcopy['Plex'] = get_sc_param(id,'Plex')
    shadowcopy['ProviderID'] = get_sc_param(id,'ProviderID')
    shadowcopy['ServiceMachine'] = get_sc_param(id,'ServiceMachine')
    shadowcopy['SetID'] = get_sc_param(id,'SetID')
    shadowcopy['State'] = get_sc_param(id,'State')
    shadowcopy['Transportable'] = get_sc_param(id,'Transportable')
    shadowcopy['VolumeName'] = get_sc_param(id,'VolumeName')
    return shadowcopy
  end

  #
  # Return the value of the +param_name+ for the volume shadow copy
  # specified by +id+
  #
  def get_sc_param(id,param_name)
    result = wmic_query("shadowcopy where(id=#{id}) get #{param_name}")
    result.gsub!(param_name,'')
    result.gsub!(/\s/,'')
  end

  #
  # Return the value of the shadowstorage parameter specified by
  # +param_name+
  #
  def vss_get_storage_param(param_name)
    result = wmic_query("shadowstorage get #{param_name}")
    result.gsub!(param_name,'')
    result.gsub!(/\s/,'')
  end

  #
  # Set the shadowstorage MaxSpace parameter to +bytes+ size
  #
  def vss_set_storage(bytes)
    result = wmic_query("shadowstorage set MaxSpace=\"#{bytes}\"")
    if result.include?("success")
      return true
    else
      return false
    end
  end

  #
  # Create a new shadow copy of the volume specified by +volume+
  #
  def create_shadowcopy(volume)
    result = wmic_query("shadowcopy call create \"ClientAccessible\", \"#{volume}\"")

    retval = result.match(/ReturnValue = (\d)/)
    if retval.nil?
      print_error('Shadow copy creation failed')
      return
    end

    case retval[1].to_i
    when 0
      print_status("ShadowCopy created successfully")
      sc_id = result.match(/ShadowID = ("\{\w{8}-\w{4}-\w{4}-\w{4}-\w{12}\}")/)
      return sc_id[1]
    when 1
      print_error("Access Denied")
    when 2
      print_error("Invalid Argument")
    when 3
      print_error("Specified volume not found")
    when 4
      print_error("Specified volume not supported")
    when 5
      print_error("Unsupported shadow copy context")
    when 6
      print_error("Insufficient Storage")
    when 7
      print_error("Volume is in use")
    when 8
      print_error("Maximum number of shadow copies reached")
    when 9
      print_error("Another shadow copy operation is already in progress")
    when 10
      print_error("Shadow copy provider vetoed the operation")
    when 11
      print_error("Shadow copy provider not registered")
    when 12
      print_error("Shadow copy provider failure")
    else
      print_error("Unknown error")
    end
    return
  end

  #
  # Start the Volume Shadow Service
  #
  def start_vss
    vss_state = wmic_query('Service where(name="VSS") get state')
    if vss_state=~ /Running/
      print_status("Volume Shadow Copy service is running.")
    else
      print_status("Volume Shadow Copy service not running. Starting it now...")
      if service_restart("VSS", START_TYPE_MANUAL)
        print_good("Volume Shadow Copy started successfully.")
      else
        print_error("Insufficient privileges to start the service!")
        return false
      end
    end
    unless start_swprv
      return false
    end
    return true
  end

  def start_swprv
    vss_state = wmic_query('Service where(name="swprv") get state')
    if vss_state=~ /Running/
      print_status("Software Shadow Copy service is running.")
    else
      print_status("Software Shadow Copy service not running. Starting it now...")
      if service_restart("swprv", START_TYPE_MANUAL)
        print_good("Software Shadow Copy started successfully.")
      else
        print_error("Insufficient privileges to start the service!")
        return false
      end
    end
    return true
  end

end
end
end
end

