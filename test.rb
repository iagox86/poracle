$LOAD_PATH << File.dirname(__FILE__) # A hack to make this work on 1.8/1.9

require 'Pooracle'

# Test a known string just so we can display it to the user
puts("Decrypting 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'):")
mod = TestModule.new()
mod.aes_128_from_data("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
puts(Pooracle.new(mod).decrypt)

# Test a known string from only the ciphertext
puts("Decrypting 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' using only the ciphertext")
mod = TestModule.new()
mod.aes_128_from_enc("\xd0\x98\xc0\xd4\x86\x82\x1e\x51\x11\xf2\x6d\x6b\xbe\xe6\xcd\xfe\xd4\xeb\xc0\x85\xa8\x9e\x5f\xe1\xcb\x50\xf7\x48\x3d\x90\x55\x1d", "\xb2\x89\xe6\x14\xfb\xb2\x2a\x37\x71\x60\x5b\xeb\x91\x73\xcb\x08", "\x0b\xaa\x90\x31\x48\x9a\xf7\x3e\xcc\xd9\xa0\xdb\x59\xdc\xbb\xc8")
puts(Pooracle.new(mod).decrypt)

# Test a bunch of random strings with aes-128
0.upto(4) do
  testdata = (0..rand(64)).map{(rand(0x7E - 0x20) + 0x20).chr}.join
  mod = TestModule.new()
  mod.aes_128_from_data(testdata)

  result = Pooracle.new(mod).decrypt
  if(result != testdata)
    puts("ERROR: Data did not decrypt properly!")
    exit
  end
  puts(Util.strclean(result))
  puts()
  puts()
end

# Test a string that won't decrypt properly
mod = TestModule.new()
mod.gen_aes_128(nil, 'A' * 16, 'A' * 16, 'A' * 20)
result = Pooracle.new(mod).decrypt
if(!result.nil?)
  puts("Invalid encrypted string test failed!")
  exit
else
  puts("Invalid encrypted string test passed!")
end

