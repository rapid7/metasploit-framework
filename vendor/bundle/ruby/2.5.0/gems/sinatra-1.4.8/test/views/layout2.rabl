node(:qux) do
  ::JSON.parse(yield)
end
