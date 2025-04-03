require 'socket'
require 'time'

HOST='localhost'
PORT=1540

server = TCPServer.new(HOST, PORT)
client = server.accept    # Wait for a client to connect
client.puts "Server: Connection established"
loop do
  client.puts "Hello !"
  client.puts "Time is #{Time.now}"
end
client.close

print("Server: Goodbye!")
