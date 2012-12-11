$LOAD_PATH << File.dirname(__FILE__) # A hack to make this work on 1.8/1.9

require 'Pooracle'

# Do a visible test for AES-256
print("Testing AES-256 visibly...")
mod = TestModule.new()
mod.verbose = true
mod.delay = 0.0001
mod.aes_256_from_data("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
p = Pooracle.new(mod)
p.verbose = true
result = p.decrypt
if(result == "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
  puts("Passed!")
else
  puts("Failed!")
  exit
end

# Do a visible test
print("Testing AES-128 visibly...")
mod = TestModule.new()
mod.verbose = true
mod.delay = 0.0001
mod.aes_128_from_data("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
p = Pooracle.new(mod)
p.verbose = true
result = p.decrypt
if(result == "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
  puts("Passed!")
else
  puts("Failed!")
end

# Test a known string just so we can display it to the user
print("Testing AES-128 with a known plaintext...")
mod = TestModule.new()
mod.aes_128_from_data("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
p = Pooracle.new(mod)
result = p.decrypt
if(result == "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
  puts("Passed!")
else
  puts("Failed!")
end

# Test a known string from only the ciphertext
print("Testing AES-128 with only ciphertext...")
mod = TestModule.new()
mod.aes_128_from_enc("\xd0\x98\xc0\xd4\x86\x82\x1e\x51\x11\xf2\x6d\x6b\xbe\xe6\xcd\xfe\xd4\xeb\xc0\x85\xa8\x9e\x5f\xe1\xcb\x50\xf7\x48\x3d\x90\x55\x1d", "\xb2\x89\xe6\x14\xfb\xb2\x2a\x37\x71\x60\x5b\xeb\x91\x73\xcb\x08", "\x0b\xaa\x90\x31\x48\x9a\xf7\x3e\xcc\xd9\xa0\xdb\x59\xdc\xbb\xc8")
p = Pooracle.new(mod)
result = p.decrypt
if(result == "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
  puts("Passed!")
else
  puts("Failed!")
end

# Test a bunch of random strings with aes-128
0.upto(8) do
  print("Testing AES-128 with a random string...")
  testdata = (0..rand(64)).map{(rand(0x7E - 0x20) + 0x20).chr}.join

  mod = TestModule.new()
  mod.aes_128_from_data(testdata)

  p = Pooracle.new(mod)
  result = p.decrypt()
  if(result == testdata)
    puts("Passed!")
  else
    puts("Failed!")
  end
end

# Test a bunch of random strings with aes-256
0.upto(8) do
  print("Testing AES-256 with a random string...")
  testdata = (0..rand(64)).map{(rand(0x7E - 0x20) + 0x20).chr}.join

  mod = TestModule.new()
  mod.aes_256_from_data(testdata)

  p = Pooracle.new(mod)
  result = p.decrypt()
  if(result == testdata)
    puts("Passed!")
  else
    puts("Failed!")
  end
end

# Test a string that won't decrypt properly
print("Testing an invalid ciphertext string...")
mod = TestModule.new()
mod.aes_128_from_enc('A' * 32, 'A' * 16, 'A' * 16)
result = Pooracle.new(mod).decrypt
if(result.nil?)
  puts("Passed!")
  exit
else
  puts("Failed!")
end

