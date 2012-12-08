$LOAD_PATH << '.' # A hack to make this work on 1.8/1.9

require 'Pooracle'

0.upto(256) do
  testdata = (0..rand(64)).map{rand(255).chr}.join
  mod = TestModule.new(testdata)
  result = Pooracle.new(mod).decrypt
  if(result != testdata)
    puts("ERROR: Data did not decrypt properly!")
    exit
  end
  puts(result.unpack("H*"))
end

puts(Pooracle.new(TestModule.new("ABCDEFGHIJKLMNOPQRSTUVWXYZ")).decrypt)

