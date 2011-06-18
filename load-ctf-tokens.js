var net = require('net'),
    redis = require('redis'),
    
    // ctf message deserialization states...
    EXPECTING_CTF_FRAME_START = 1,
    EXPECTING_CTF_PROTOCOL_SIGNATURE = 2,
    EXPECTING_CTF_PAYLOAD_SIZE = 3,
    EXPECTING_CTF_PAYLOAD = 4,
    EXPECTING_CTF_FRAME_END = 5,
    
	FRAME_START 		= exports.FRAME_START 			= 0x04, // ctf start of frame byte
	FRAME_END 			= exports.FRAME_END 			= 0x03, // ctf end of frame byte
	PROTOCOL_SIGNATURE 	= exports.PROTOCOL_SIGNATURE	= 0x20, // ctf protocol signature byte

    ctfState = EXPECTING_CTF_FRAME_START, // current ctf state
    payloadBuffer = null, // buffer to hold ctf payload
    payloadBytesLeft = 0, // ctf payload bytes left to be processed
    payloadSizeBuffer = null, // buffer to hold ctf payload size
    payloadSizeBytesLeft = 0, // ctf payload size bytes left to be processed
    
    done = 0,
    
    // List of CTF commands
    ctfCommandList = 
	[ 
		"5022=LoginUser|5028=pfcanned|5029=cypress|5026=1",
		"5022=ListAvailableTokens|5026=2"
    ];
    
// redis connection
var redisdb = redis.createClient();

redisdb.on("error", function (err) {
    console.log("Redis Error " + err);
});

function updateDataDictionary(ctfmsg) {
	var toknum = null,
		tokname = null;
		
	ctfmsg.split("|").forEach(function(token) {
		var tvpair = token.split("=");
		if (tvpair[0] == "5035") {
			toknum = tvpair[1]
		} else if (tvpair[0] == "5010") {
			tokname = tvpair[1]
		}
	});
	
	if (toknum != null && tokname != null) {
		redisdb.hset("ctf-data-dictionary", toknum, tokname);
	}
}

// ctf connection
var client = net.createConnection(4011, "trialdata.interactivedata-rts.com"); // 941

/* 
 * ctf connection handlers
 */
client.addListener("connect", function () {
    //console.log("connection is established with ctf server...");
    //client.setEncoding('ascii');
    
	ctfCommandList.forEach(function(cmd, pos) {
        client.write(serialize(cmd));
	});
});

client.addListener("data", function (chunk) {
    //console.log("data is received from ctf server..." + chunk.toString());
    deserialize(chunk);
});

client.addListener("end", function () {
    console.log("ctf server disconnected...");
	process.exit();
});

/**
 * Function to convert a number into 32-bit buffer
 *
 * @param       number  number to convert
 * @return      buffer  32 bits
 * @access      public
 */
function to32Bits(num) {
	var bytes = new Buffer(4),
  		i = 4;

  	do {
    	bytes[--i] = num & (255);
     	num = num>>8;
  	} while ( i )
	//console.log(bytes);
  	return bytes;
}

/**
 * Function to convert a 32-bit buffer into a number
 *
 * @param      buffer  32 bits
 * @return     number  number representing the 32 bits
 * @access     public
 */
function toNum(buf) {
  	var	i = 4;
		num = 0;
		numBits = 0;
		
  	do {
		num += (buf[--i]<<numBits);
		numBits += 8;
  	} while ( i )
	//console.log(num);
  	return num;
}

/**
 * serialize(string)
 * Creates a ctf message out of a name/value paired string.
 * For e.g. "5022=LoginUser|5028=plusserver|5029=plusserver|5026=1"
 *
 * @param       string  ctf message
 * @return      buffer  serialized ctf message
 * @access      public
 */
function serialize (str) {

	var msglen = Buffer.byteLength(str, 'ascii'),
		ctfmsg = new Buffer(msglen + 7); //1 STX, 1 PROTO SIG, 4 LEN, 1 ETX

	// start of the frame - 1 byte
	ctfmsg[0] = FRAME_START;

	// protocol version - 1 byte
	ctfmsg[1] = PROTOCOL_SIGNATURE;

	// lenght of the payload - 4 bytes
	to32Bits(msglen).copy(ctfmsg, 2, 0, 4);

	// payload
	ctfmsg.write(str, 6, 'ascii');

	ctfmsg[ctfmsg.length-1] = FRAME_END;

	console.log("<=" + ctfmsg);
	return ctfmsg;
}

/**
 * deserialize(buffer)
 * Parses a ctf message stream into name/value paired strings.
 * For e.g. "5022=LoginUser|5028=plusserver|5029=plusserver|5026=1"
 *
 * @param       buffer  raw ctf messages
 * @return      string  ctf message
 * @access      public
 */
function deserialize (buf) {
    //console.log("Length: " + buf.length);
    for (var i = 0; i < buf.length; i++) {
        switch (ctfState) {
            case EXPECTING_CTF_FRAME_START:
                if (buf[i] == FRAME_START) {
                    ctfState = EXPECTING_CTF_PROTOCOL_SIGNATURE;
                } else {
                    console.log("Error: expecting ctf start byte, received " + buf[i]);
                    // TODO
                }
            break;
            
            case EXPECTING_CTF_PROTOCOL_SIGNATURE:
                if (buf[i] == PROTOCOL_SIGNATURE) {
                    ctfState = EXPECTING_CTF_PAYLOAD_SIZE;
                    payloadSizeBuffer = new Buffer(4);
                    payloadSizeBytesLeft = 4;
                } else {
                    console.log("Error: expecting ctf protocol signature byte, received " + buf[i]);
                    // TODO
                }
            break;
            
            case EXPECTING_CTF_PAYLOAD_SIZE:
                // continute to collect payload size bytes
                payloadSizeBuffer[payloadSizeBuffer.length - payloadSizeBytesLeft--] = buf[i];
                
                if (payloadSizeBytesLeft == 0) {
                    // done collecting payload size bytes
                    //console.log(payloadSizeBuffer);
                    var payloadSize = toNum(payloadSizeBuffer);
                    //console.log("payload size = ", payloadSize);
                    payloadBuffer = new Buffer(payloadSize);
                    payloadBytesLeft = payloadSize;
                    ctfState = EXPECTING_CTF_PAYLOAD;
                }
            break;
            
            case EXPECTING_CTF_PAYLOAD:
                payloadBuffer[payloadBuffer.length - payloadBytesLeft--] = buf[i];
                if (payloadBytesLeft == 0) {
                    //console.log("New CTF Message: " + payloadBuffer);
                    ctfState = EXPECTING_CTF_FRAME_END;
                }
            break;
            
            case EXPECTING_CTF_FRAME_END:
                if (buf[i] == FRAME_END) {
					var payload = payloadBuffer.toString();
                    //console.log("=>" + payload);
					if (payload == "5026=2|5001=0") {
						client.end();
					} else {
						updateDataDictionary(payload);
					}
                    ctfState = EXPECTING_CTF_FRAME_START;
                } else {
                    console.log("Error: expecting ctf frame end byte, received " + buf[i]);
                    // TODO
                }
            break;
        }
    }
}
