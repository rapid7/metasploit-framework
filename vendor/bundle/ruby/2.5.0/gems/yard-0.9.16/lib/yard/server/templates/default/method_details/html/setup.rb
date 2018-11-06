# frozen_string_literal: true
def init
  super
  sections.place(:permalink).after_any(:method_signature)
end
