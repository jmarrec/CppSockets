require 'socket'

HOST = 'localhost'
PORT = 1540

s = TCPSocket.new(HOST, PORT)

while line = s.recv(1024) # Read lines from socket
  puts line         # and print them
end

s.close             # close socket when done
