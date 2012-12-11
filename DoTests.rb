$LOAD_PATH << File.dirname(__FILE__) # A hack to make this work on 1.8/1.9

require 'openssl'

require 'LocalTestModule'
require 'RemoteTestModule'
require 'Pooracle'

# Perform local checks
ciphers = OpenSSL::Cipher::ciphers.grep(/cbc/)
passes = 0
failures = 0
ciphers.each do |cipher|
  # Create the test module
  print("> #{cipher} with known data... ")
  if(Pooracle.new(LocalTestModule.new(cipher, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")).decrypt() == "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    passes += 1
    puts "Passed!"
  else
    failures += 1
    puts "Failed!"
  end

  (0..64).to_a.shuffle[0, 16].each do |i|
    print("> #{cipher} with random data (#{i} bytes)... ")

    data = (0..i).map{(rand(0x7E - 0x20) + 0x20).chr}.join
    if(Pooracle.new(LocalTestModule.new(cipher, data)).decrypt() == data)
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

# Attempt a remote check
puts("Starting remote test (this requires RemoteTestServer.rb to be running on localhost:20222)")
p = Pooracle.new(RemoteTestModule.new)
p.verbose = true
p.decrypt()

