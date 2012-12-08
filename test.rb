$LOAD_PATH << '.' # A hack to make this work on 1.8/1.9

require 'Pooracle'

# Test a string that won't decrypt properly
result = Pooracle.new(TestModule.new(nil, 'A' * 16, 'A' * 16, 'A' * 64)).decrypt
if(!result.nil?)
  puts("Invalid encrypted string test failed!")
  exit
else
  puts("Invalid encrypted string test passed!")
end

# Test a bunch of random strings
0.upto(4) do
  testdata = (0..rand(64)).map{rand(255).chr}.join
  mod = TestModule.new(testdata)
  result = Pooracle.new(mod).decrypt
  if(result != testdata)
    puts("ERROR: Data did not decrypt properly!")
    exit
  end
  puts(result.unpack("H*"))
  puts()
  puts()
end

# Test a known string just so we can display it to the user
puts("Decrypting 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'):")
puts(Pooracle.new(TestModule.new("ABCDEFGHIJKLMNOPQRSTUVWXYZ")).decrypt)

