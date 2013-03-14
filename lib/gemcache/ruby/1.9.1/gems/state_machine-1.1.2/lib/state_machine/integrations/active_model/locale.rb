{:en => {
  :activemodel => {
    :errors => {
      :messages => {
        :invalid => StateMachine::Machine.default_messages[:invalid],
        :invalid_event => StateMachine::Machine.default_messages[:invalid_event] % ['%{state}'],
        :invalid_transition => StateMachine::Machine.default_messages[:invalid_transition] % ['%{event}']
      }
    }
  }
}}
