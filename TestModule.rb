require 'AES'

class TestModule
  attr_reader :iv, :blocksize, :data

  NAME = "TestModule(tm)"

  def initialize(data, key = nil, iv = nil, encrypted_data = nil)
    @blocksize = AES::BLOCKSIZE
    @key = key.nil? ? (1..16).map{rand(255).chr}.join : key
    @iv  = iv.nil?  ? (1..16).map{rand(255).chr}.join : iv
    @data = encrypted_data.nil? ? AES.encrypt(data, @key, @iv, "AES-128-CBC") : encrypted_data

    puts()
    puts("-" * 80)
    puts("Generated test data: #{data}")
    puts("-" * 80)
    puts("key: #{@key.unpack("H*")}")
    puts("iv:  #{@iv.unpack("H*")}")
    puts("enc: #{@data.unpack("H*")}")
    puts("-" * 80)
  end

  def attempt_decrypt(iv, block)
      begin
        sleep(0.0005)
        decrypted = AES.decrypt(block, @key, iv, "AES-128-CBC")
        return true
      rescue # TODO: Be more specific
        return false
      end
  end
end

