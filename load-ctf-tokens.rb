require 'socket'
require 'redis'

$redisdb = Redis.new

def updateDataDictionary ctfmsg
  #5026=6|5035=5|5010=SYMBOL.TICKER|5012=STRING|5011=32|5002=1
	toknum = nil #=5
	tokname = nil #=SYMBOL.TICKER
	
	ctfmsg.split('|').each do |token|
			tvpair = token.split('=')
			if tvpair[0] == "5035"
				toknum = tvpair[1]
			elsif tvpair[0] == "5010"
				tokname = tvpair[1]
			end
	end
	if toknum != nil && tokname != nil
	  $redisdb.hset("ctf-data-dictionary", toknum, tokname)
  end
end

# Open TCP socket connection to plusfeed server
ctfSocket = TCPSocket::new( "trialdata.interactivedata-rts.com", 4011 )

# List of CTF commands
ctfCommandList = 
	[ 
	"5022=LoginUser|5028=pfcanned|5029=cypress|5026=1",
	"5022=ListAvailableTokens|5026=2"
	]

ctfCommandList.each do |cmd|
	# Format a CTF Message
	ctfRequest = [ 0x04, 0x20, cmd.length, cmd, 0x03].pack("ccNA*c")
	puts ctfRequest

	# Send the CTF request
	ctfSocket.send( ctfRequest, 0 )
end

ctfMessage = String.new
ctfState = :ExpectingFrameStart
payloadSizeBytes = 0
done = false
while !done
	# Read the CTF messages
	ctfResponse = ctfSocket.recv( 4*1024 )
	if ctfResponse.bytesize == 0
	  break
  end
	#puts ctfResponse
	i = 0
	until i == ctfResponse.bytesize
		case ctfState
			when :ExpectingFrameStart
				if ctfResponse.getbyte(i) == 4
					#puts "CTF Message Begin"
					ctfMessage = String.new
					ctfState = :ExpectingProtocolSignature
				else
					puts "Error: CTF protocol violated. Expecting frame start, received " + ctfResponse[i]
					break
				end
		
			when :ExpectingProtocolSignature
				if ctfResponse.getbyte(i) == 32
					payloadSizeBytes = 0
					ctfState = :ExpectingPayloadSize
				else
					puts "Error: CTF protocol violated. Expecting protocol signature, received " + ctfResponse[i]
					break
				end
		
			when :ExpectingPayloadSize
				payloadSizeBytes += 1
				if payloadSizeBytes == 4
					ctfState = :ExpectingFrameEnd
				end
			
			when :ExpectingFrameEnd
				if ctfResponse.getbyte(i) == 3
					#puts "CTF Message End"
					payload = ctfMessage.unpack("ccNA*")[3]
					#puts payload
					if "5026=2|5001=0" == payload
					  done = true
				  else
					  updateDataDictionary payload
					  ctfState = :ExpectingFrameStart
				  end
				end
		end
		ctfMessage += ctfResponse[i]
		i += 1
	end
end

# Close the socket
ctfSocket.close