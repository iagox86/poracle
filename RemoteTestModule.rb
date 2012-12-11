##
# RemoteTestModule.rb
# Created: December 10, 2012
# By: Ron Bowes
#
# A very simple implementation of a Padding Oracle module. Basically, it
# performs the attack against an instance of RemoteTestServer, which is an
# ideal padding oracle target.
##
#
require 'httparty'

class RemoteTestModule
  attr_reader :iv, :data, :blocksize

  NAME = "RemoteTestModule(tm)"

  def initialize()
    @data = HTTParty.get("http://localhost:20222/encrypt").parsed_response
    @data = [@data].pack("H*")
    @iv = nil
    @blocksize = 16
  end

  def attempt_decrypt(iv, block)
    result = HTTParty.get("http://localhost:20222/decrypt/#{iv.unpack("H*").pop}#{block.unpack("H*").pop}")

    return result.parsed_response !~ /Fail/
  end
end

