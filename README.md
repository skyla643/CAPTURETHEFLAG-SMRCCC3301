We started by establishing a connection to the challenge-and-response server using the remote() function from the pwn module.
We received the data offset value (DOV) in the form of a little-endian short (2 bytes) from the server.
We converted the 2-byte offset value to a short using the u16() function from the pwn module.
We received the challenge packet (C) (100 bytes) from the server.
We found the significant data packet (D) based on the offset value by calculating the data offset and extracting the data packet from the challenge packet.
We decoded the data packet (D) to find the correct option to form the key (K) by extracting the option select, multiple, and options from the data packet.
We calculated K by multiplying the multiple with the correct option.
We converted K to a little-endian long (8 bytes) using the p64() function from the pwn module.
We sent the response K to the server using the send() function.
We received the response from the server and printed it using the recvn() function from the pwn module.
We closed the connection to the server using the close() function from the pwn module.
