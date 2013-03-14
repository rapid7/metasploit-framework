def with_deprecation_silenced(&block)
  ::ActiveSupport::Deprecation.silence do
    yield
  end
end

