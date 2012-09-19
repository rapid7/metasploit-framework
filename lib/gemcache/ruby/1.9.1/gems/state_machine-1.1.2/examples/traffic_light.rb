require 'state_machine'

class TrafficLight
  state_machine :initial => :stop do
    event :cycle do
      transition :stop => :proceed, :proceed => :caution, :caution => :stop
    end
  end
end
