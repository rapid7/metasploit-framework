module Nexpose
  module Search
    module Field

      ###### vSphere Filters ######
      # Valid Operators: IS, IS_NOT, CONTAINS, NOT_CONTAINS, STARTS_WITH
      CLUSTER = 'CLUSTER'

      # Valid Operators: IS, IS_NOT
      DATACENTER = 'DATACENTER'

      # Valid Operators: CONTAINS, NOT_CONTAINS
      GUEST_OS_FAMILY = 'GUEST_OS_FAMILY' # Also AWS Filter

      # Valid Operators: IN, NOT_IN
      IP_ADDRESS_RANGE = 'IP_ADDRESS' # Also AWS Filter

      # Valid Operators: IN, NOT_IN
      # Valid Values (See Value::PowerState): ON, OFF, SUSPENDED
      POWER_STATE = 'POWER_STATE'

      # Valid Operators: CONTAINS, NOT_CONTAINS
      RESOURCE_POOL_PATH = 'RESOURCE_POOL_PATH'

      # Valid Operators: IS, IS_NOT, CONTAINS, NOT_CONTAINS, STARTS_WITH
      VIRTUAL_MACHINE_NAME = 'VM'

      # valid Operators: IS, IS_NOT, CONTAINS, NOT_CONTAINS, STARTS_WITH
      HOST = 'HOST_NAME'

      ###### AWS Filters ######
      # Valid Operators: CONTAINS, NOT_CONTAINS
      AVAILABILITY_ZONE = 'AVAILABILITY_ZONE'

      # Valid Operators: CONTAINS, NOT_CONTAINS
      INSTANCE_ID = 'INSTANCE_ID'

      # Valid Operators: IS, IS_NOT, CONTAINS, NOT_CONTAINS, STARTS_WITH
      INSTANCE_NAME = 'INSTANCE_NAME'

      # Valid Operators: IN, NOT_IN
      INSTANCE_STATE = 'INSTANCE_STATE'

      # Valid Operators: IN, NOT_IN
      INSTANCE_TYPE = 'INSTANCE_TYPE'

      # Valid Operators: IN, NOT_IN
      REGION = 'REGION'

      ###### Mobile or Active sync Filters ######
      # Valid Operators: CONTAINS, NOT_CONTAINS
      OPERATING_SYSTEM = 'DEVICE_OPERATING_SYSTEM'

      # Valid Operators: IS, IS_NOT, CONTAINS, NOT_CONTAINS, STARTS_WITH
      USER = 'DEVICE_USER_DISPLAY_NAME'

    end

    module Value
      module PowerState
        ON        = 'poweredOn'
        OFF       = 'poweredOff'
        SUSPENDED = 'suspended'
      end
    end
  end
end
