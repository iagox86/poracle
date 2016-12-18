# encoding: ASCII-8BIT

##
# Demo.rb
# Created: February 10, 2013
# By: Ron Bowes
#
# A demo of how to use Poracle, that works against RemoteTestServer.
##
#
require 'httparty'
require './Poracle'

BLOCKSIZE = 16

poracle = Poracle.new(BLOCKSIZE, true) do |data|
  url = "http://localhost:20222/decrypt/#{data.unpack('H*').pop()}"
  result = HTTParty.get(url)

  # Return
  result.parsed_response !~ /Fail/
end

data = HTTParty.get("http://localhost:20222/encrypt").parsed_response
print "Trying to decrypt: %s" % data

result = poracle.decrypt([data].pack('H*'))
puts("-----------------------------")
puts("Decryption result")
puts("-----------------------------")
puts result
puts("-----------------------------")
puts()

data = "The most merciful thing in the world, I think, is the inability of the human mind to correlate all its contents."
print "Trying to encrypt: %s" % data
result = poracle.encrypt(data)

puts("-----------------------------")
puts("Encrypted string")
puts("-----------------------------")
puts result.unpack('H*')
puts("-----------------------------")
puts()
