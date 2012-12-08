$LOAD_PATH << '.' # A hack to make this work on 1.8/1.9

require 'Pooracle'

# Test a known string just so we can display it to the user
puts("Decrypting 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'):")
puts(Pooracle.new(TestModule.new("ABCDEFGHIJKLMNOPQRSTUVWXYZ")).decrypt)

# Test a string that won't decrypt properly
result = Pooracle.new(TestModule.new(nil, 'A' * 16, 'A' * 16, 'A' * 20)).decrypt
if(!result.nil?)
  puts("Invalid encrypted string test failed!")
  exit
else
  puts("Invalid encrypted string test passed!")
end

# Test a bunch of random strings
0.upto(4) do
  testdata = (0..rand(64)).map{(rand(0x80 - 0x20) + 0x20).chr}.join
  mod = TestModule.new(testdata)
  result = Pooracle.new(mod).decrypt
  if(result != testdata)
    puts("ERROR: Data did not decrypt properly!")
    exit
  end
  puts(Util.strclean(result))
  puts()
  puts()
end


puts("Decrypting 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' using only the ciphertext")
puts(Pooracle.new(TestModule.new(nil, "\xb2\x89\xe6\x14\xfb\xb2\x2a\x37\x71\x60\x5b\xeb\x91\x73\xcb\x08", "\x0b\xaa\x90\x31\x48\x9a\xf7\x3e\xcc\xd9\xa0\xdb\x59\xdc\xbb\xc8", "\xd0\x98\xc0\xd4\x86\x82\x1e\x51\x11\xf2\x6d\x6b\xbe\xe6\xcd\xfe\xd4\xeb\xc0\x85\xa8\x9e\x5f\xe1\xcb\x50\xf7\x48\x3d\x90\x55\x1d")).decrypt)

