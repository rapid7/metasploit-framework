local clock = os.clock
function sleep(n)  -- seconds
  local t0 = clock()
  while clock() - t0 <= n do end
end

file = io.open("writer.txt","w")
for i=1,1000 do
file:write(i)
file:flush()
sleep(1)
end

