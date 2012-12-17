$LOAD_PATH << File.dirname(__FILE__) # A hack to make this work on 1.8/1.9

require 'openssl'

require 'LocalTestModule'
require 'RemoteTestModule'
require 'Poracle'

# Perform local checks
ciphers = OpenSSL::Cipher::ciphers.grep(/cbc/)
ciphers = ["AES-128-CBC", "DES-CBC", "AES-256-CBC"] # TODO: Testing
#srand(123456)

passes = 0
failures = 0
guesses = 0

print("> AES-256-CBC with known data... ")
d = Poracle.new(LocalTestModule.new("AES-256-CBC", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")).decrypt()
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
0.upto(24) do
  print("> AES-128-CBC that requires backtracking...")

  data_length = rand(15).to_i + 1
  data = (1..data_length).map{rand(255).to_i.chr}.join
  cipher = "AES-128-CBC"
  #iv  = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00"
  iv  = (1..16).map{rand(255).to_i.chr}.join
  iv[14] = ((16 - data_length) ^ 2).chr
  p = Poracle.new(LocalTestModule.new(cipher, data, nil, iv))
  if(p.decrypt() == data)
    passes += 1
    puts "Passed!"
  else
    failures += 1
    puts "Failed!"
  end
end

# Do a bunch of very short strings
(0..256).to_a.each do |i|
  data = (0..4).map{rand(255).to_i.chr}.join
  p = Poracle.new(LocalTestModule.new(ciphers.shuffle[0], data, nil, nil, true), true)
  if(p.decrypt() == data)
    passes += 1
    puts "Passed!"
  else
    failures += 1
    puts "Failed!"
  end
end

# Try the different ciphers
ciphers.each do |cipher|
  (0..64).to_a.shuffle[0, 8].each do |i|
    print("> #{cipher} with random data (#{i} bytes)... ")

    data = (0..i).map{(rand(0x7E - 0x20) + 0x20).chr}.join
    p = Poracle.new(LocalTestModule.new(cipher, data))
    if(p.decrypt() == data)
      passes += 1
      puts "Passed!"
    else
      failures += 1
      puts "Failed!"
    end

    guesses += p.guesses
  end
end

puts("Ciphers tested: #{ciphers.join(", ")}")
puts("Tests passed: #{passes}")
puts("Tests failed: #{failures}")
puts("Total number of guesses: #{guesses} (should be 122895)")

# Attempt a remote check
puts("Starting remote test (this requires RemoteTestServer.rb to be running on localhost:20222)")
p = Poracle.new(RemoteTestModule.new)
p.verbose = true
p.decrypt()

