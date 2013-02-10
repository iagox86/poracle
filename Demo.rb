##
# Demo.rb
# Created: February 10, 2013
# By: Ron Bowes
#
# A demo of how to use Poracle, that works against RemoteTestServer.
##
#
require 'httparty'
require './poracle'

class DemoModule
  attr_reader :iv, :data, :blocksize

  NAME = "DemoModule(tm)"

  # This function should load @data, @iv, and @blocksize appropriately
  def initialize()
    @data = HTTParty.get("http://localhost:20222/encrypt").parsed_response
    # Parse 'data' here
    @data = [@data].pack("H*")
    @iv = nil
    @blocksize = 16
  end

  # This should make a decryption attempt and return true/false
  def attempt_decrypt(data)
    result = HTTParty.get("http://localhost:20222/decrypt/#{data.unpack("H*").pop}").parsed_response

    # Match 'result' appropriately
    return result !~ /Fail/
  end

  # Optionally define a character set, with the most common characters first
  def character_set()
    return ' eationsrlhdcumpfgybw.k:v-/,CT0SA;B#G2xI1PFWE)3(*M\'!LRDHN_"9UO54Vj87q$K6zJY%?Z+=@QX&|[]<>^{}'.chars.to_a
  end
end

mod = DemoModule.new
puts "DECRYPTED: #{Poracle.decrypt(mod, mod.data, mod.iv, true)}"

