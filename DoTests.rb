$LOAD_PATH << File.dirname(__FILE__) # A hack to make this work on 1.8/1.9

require 'openssl'

require 'LocalTestModule'
require 'RemoteTestModule'
require 'Poracle'

if(ARGV[0] == 'remote')
  # Attempt a remote check
  puts("Starting remote test (this requires RemoteTestServer.rb to be running on localhost:20222)")
  begin
    mod = RemoteTestModule.new
    puts Poracle.decrypt(mod, mod.data, mod.iv, true, true)
  rescue Exception => e
    puts("Couldn't connect to remote server: #{e}")
  end
end

# Perform local checks
ciphers = OpenSSL::Cipher::ciphers.grep(/cbc/)
srand(123456)

passes = 0
failures = 0

print("> AES-256-CBC with known data... ")
mod = LocalTestModule.new("AES-256-CBC", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
d = Poracle.decrypt(mod, mod.ciphertext, mod.iv, true, true)
if(d == "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
  passes += 1
  puts "Passed!"
else
  failures += 1
  puts "Failed!"
  puts "Expected: ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  puts "Received: #{d}"
  puts
  puts "First test failed; bailing"
  exit
end

# Test strings that require backtracking
0.upto(72) do
  print("> AES-128-CBC that requires backtracking...")

  data_length = rand(15).to_i + 1
  data = (1..data_length).map{(rand(0x60) + 0x20).to_i.chr}.join
  cipher = "AES-128-CBC"
  #iv  = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00"
  iv  = (1..16).map{rand(255).to_i.chr}.join
  iv[14] = ((16 - data_length) ^ 2).chr
  mod = LocalTestModule.new(cipher, data, nil, iv)
  d = Poracle.decrypt(mod, mod.ciphertext, mod.iv, false, true)
  if(d == data)
    passes += 1
    puts "Passed!"
  else
    failures += 1
    puts "Failed!"
  end
end

# Do a bunch of very short strings
(0..512).to_a.each do |i|
  data = (0..rand(8)).map{rand(255).to_i.chr}.join
  cipher = ciphers.shuffle[0]
  print("> #{cipher} with random short data... ")
  mod = LocalTestModule.new(cipher, data, nil, nil)
  d = Poracle.decrypt(mod, mod.ciphertext, mod.iv)
  if(d == data)
    passes += 1
    puts "Passed!"
  else
    failures += 1
    puts "Failed!"
  end
end

# Try the different ciphers
ciphers.each do |cipher|
  (0..128).to_a.shuffle[0, 8].each do |i|
    print("> #{cipher} with random data (#{i} bytes)... ")

    data = (0..i).map{(rand(0x7E - 0x20) + 0x20).chr}.join
    mod = LocalTestModule.new(cipher, data)
    d = Poracle.decrypt(mod, mod.ciphertext, mod.iv, false, true)
    if(d == data)
      passes += 1
      puts "Passed!"
    else
      failures += 1
      puts "Failed!"
    end
  end
end

puts("Ciphers tested: #{ciphers.join(", ")}")
puts("Tests passed: #{passes}")
puts("Tests failed: #{failures}")


