$LOAD_PATH << File.dirname(__FILE__) # A hack to make this work on 1.8/1.9

require 'openssl'

require 'LocalTestModule'
require 'RemoteTestModule'
require 'Poracle'

# Perform local checks
ciphers = OpenSSL::Cipher::ciphers.grep(/cbc/)
ciphers = ["AES-128-CBC", "DES-CBC", "AES-256-CBC"] # TODO: Testing
srand(123456)

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

print("> Testing some data that causes backtracking in DES-CBC...")
d = Poracle.new(LocalTestModule.new("DES-CBC", "5w4.x#bgIyW-8fYFZC6@_]@ZHx{", "\x8f\x8a\xab\x27\x22\xb6\x28\xbe\x26\x5c\x62\x04\x4a\xc5\x3a\x7b", "\x2d\x28\x9c\xc6\x82\xd1\x99\xdf\x17\x02\xe9\xbd\x3e\x02\x64\x92")).decrypt()
if(d == "5w4.x#bgIyW-8fYFZC6@_]@ZHx{")
  passes += 1
  puts "Passed!"
else
  failures += 1
  puts "Failed!"
  puts "Expected: 5w4.x#bgIyW-8fYFZC6@_]@ZHx{"
  puts "Received: #{d}"
  exit
end

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

