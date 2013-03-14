require 'tempfile'

# Define where state machine descriptions will be rendered
def init
  super
  sections.place(:state_machine_details).before(:children)
end

# Renders state machine details in the main content of the class's documentation
def state_machine_details
  erb(:state_machines) if state_machines
end

# Gets a list of state machines prased for this class
def state_machines
  @state_machines ||= begin
    if state_machines = object['state_machines']
      state_machines.each do |name, machine|
        serializer.serialize(state_machine_image_path(machine), machine[:image]) if machine[:image]
      end
    end
  end
end

# Generates the image path for the given machine's visualization
def state_machine_image_path(machine)
  base_path = File.dirname(serializer.serialized_path(object))
  image_name = "#{object.name}_#{machine[:name]}"
  "#{File.join(base_path, image_name)}.png"
end
