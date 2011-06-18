import socket
import struct

EXPECTING_CTF_FRAME_START = 1
EXPECTING_CTF_PROTOCOL_SIGNATURE = 2
EXPECTING_CTF_PAYLOAD_SIZE = 3
EXPECTING_CTF_PAYLOAD = 4
EXPECTING_CTF_FRAME_END = 5
ctfState = EXPECTING_CTF_FRAME_START
payloadSizeBuffer = ''
payloadSizeBytesLeft = 0
payload = ''

# List of CTF commands
ctfCommandList = [ 
	"5022=LoginUser|5028=pfcanned|5029=cypress|5026=1",
	"5022=ListAvailableTokens|5026=2"
	]

#def updateDataDictionary(payload):

# Open TCP socket connection to plusfeed server
ctfSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ctfSocket.connect(("trialdata.interactivedata-rts.com", 4011))
for cmd in ctfCommandList:
	# Send the CTF request
	ctfSocket.send('\x04')
	ctfSocket.send('\x20')
	ctfSocket.send(struct.pack('!L', len(cmd)))
	ctfSocket.send(cmd)
	ctfSocket.send('\x03')

done = False
while not done:
    data = ctfSocket.recv(1024)
    if data != '':
        print data
		i = 0
		while i < len(data):
			if ctfState == EXPECTING_CTF_FRAME_START:
				if data[i] == '\x04':
					ctfState = EXPECTING_CTF_PROTOCOL_SIGNATURE
				else:
					print "Error: CTF protocol violated. Expecting frame start, received " + data[i]
					break
			elif ctfState == EXPECTING_CTF_PROTOCOL_SIGNATURE:
				if data[i] == '\x20':
                    payloadSizeBuffer = ''
                    payloadSizeBytesLeft = 4
					ctfState = EXPECTING_CTF_PAYLOAD_SIZE
				else:
					print "Error: CTF protocol violated. Expecting protocol signature, received " + data[i]
					break
			elif ctfState == EXPECTING_CTF_PAYLOAD_SIZE:
            	#continute to collect payload size bytes
                payloadSizeBuffer += data[i]
				payloadSizeBytesLeft--
				
                if payloadSizeBytesLeft == 0:
                    #done collecting payload size bytes
                    payloadSize = struct.unpack('!L', payloadSizeBuffer)
                    payloadBytesLeft = payloadSize[0]
                    payload = ''
                    ctfState = EXPECTING_CTF_PAYLOAD
            elif ctfState == EXPECTING_CTF_PAYLOAD:
                payload += data[i]
				payloadBytesLeft--
                if payloadBytesLeft == 0:
           			print payload
         			ctfState = EXPECTING_CTF_FRAME_END
	        elif ctfState == EXPECTING_CTF_FRAME_END:
                if data[i] == '\x03':
					if payload == "5026=2|5001=0":
						ctfSocket.close()
					else:
						#updateDataDictionary(payload)
					
                    ctfState = EXPECTING_CTF_FRAME_START
                else:
                    print "Error: expecting ctf frame end byte, received " + data[i]
			i++
    else:
        break