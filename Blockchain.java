/*--------------------------------------------------------

1. Name / Date: Mohammed Ali Hussain Siddique / 11-03-2020

2. Java version - "11.0.8" 2020-07-14

3. Precise examples / instructions to run this program:

Compile and run the command - 
javac -cp "gson-2.8.2.jar" Blockchain.java
java -cp ".:gson-2.8.2.jar" Blockchain 0,
java -cp ".:gson-2.8.2.jar" Blockchain 1, 
java -cp ".:gson-2.8.2.jar" Blockchain 2 
for each Process in separate shells.  

4. Use to run program: 
Blockchain.java

----------------------------------------------------------*/

// Importing the libraries
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;
import java.security.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Type;
import java.net.ServerSocket;
import java.net.Socket;
import com.google.gson.reflect.TypeToken;
import com.google.gson.Gson;

class BlockRecord {

	// values for a block record
	String BlockID;
	String TimeStamp;
	String CreationProcessID;
	String VerificationProcessID;
	String PreviousHash; 
	String RandomSeed; 
	String WinningHash;
	String Fname;
	String Lname;
	String SSNum;
	String DOB;
	String Diag;
	String Treat;
	String Rx;
	String signedBlockID;
	String signedWinningHash;
	int blockNumber = 0;

	// getters and setters for all the fields in the blockrecord. 
	public String getBlockID() {
		return BlockID;
	}

	public void setBlockID(String BID) {
		this.BlockID = BID;
	}

	public String getTimeStamp() {
		return TimeStamp;
	}

	public void setTimeStamp(String TS) {
		this.TimeStamp = TS;
	}

	public String getVerificationProcessID() {
		return VerificationProcessID;
	}

	public void setVerificationProcessID(String VID) {
		this.VerificationProcessID = VID;
	}

	public String getPreviousHash() {
		return this.PreviousHash;
	}

	public void setPreviousHash(String PH) {
		this.PreviousHash = PH;
	}

	public String getLname() {
		return Lname;
	}

	public void setLname(String LN) {
		this.Lname = LN;
	}

	public String getFname() {
		return Fname;
	}

	public void setFname(String FN) {
		this.Fname = FN;
	}

	public String getSSNum() {
		return SSNum;
	}

	public void setSSNum(String SS) {
		this.SSNum = SS;
	}

	public String getDOB() {
		return DOB;
	}

	public void setDOB(String RS) {
		this.DOB = RS;
	}

	public String getDiag() {
		return Diag;
	}

	public void setDiag(String D) {
		this.Diag = D;
	}

	public String getTreat() {
		return Treat;
	}

	public void setTreat(String Tr) {
		this.Treat = Tr;
	}

	public String getRx() {
		return Rx;
	}

	public void setRx(String Rx) {
		this.Rx = Rx;
	}

	public String getRandomSeed() {
		return RandomSeed;
	}

	public void setRandomSeed(String RS) {
		this.RandomSeed = RS;
	}

	public String getWinningHash() {
		return WinningHash;
	}

	public void setWinningHash(String WH) {
		this.WinningHash = WH;
	}

	public String getCreationProcessID() {
		return CreationProcessID;
	}

	public void setCreationProcessID(String creationProcessID) {
		CreationProcessID = creationProcessID;
	}

	public String getSignedBlockID() {
		return signedBlockID;
	}

	public void setSignedBlockID(String signedBlockID) {
		this.signedBlockID = signedBlockID;
	}

	public String getSignedWinningHash() {
		return signedWinningHash;
	}

	public void setSignedWinningHash(String signedWinningHash) {
		this.signedWinningHash = signedWinningHash;
	}

	public int getBlockNumber() {
		return blockNumber;
	}

	public void setBlockNumber(int blockNumber) {
		this.blockNumber = blockNumber;
	}

}

class Blockchain {
	static Integer pnum;
	static PrivateKey privateKey;
	static Integer publicKeyPort = 4710;
	static Integer unverifiedBlockPort = 4820;
	static Integer blockChainPort = 4930;
	Boolean alreadyVerified = false;
	String currentBlock = "";

	static HashMap<String, String> publicKeys = new HashMap<>(); //Hashmap for storing all the public keys for individual processes
	static ArrayList<BlockRecord> blockChain = new ArrayList<BlockRecord>(); // Final BlockChain. 
	BlockingQueue<BlockRecord> unverifiedQueue = new PriorityBlockingQueue<>(12, BlockTSComparator); //Priority Queue. 

	Blockchain() { // Constructor initialising the first empty block with hard coded values. 
		BlockRecord initialBlock = new BlockRecord();
		initialBlock.setBlockNumber(0);
		initialBlock.setBlockID(new String(UUID.randomUUID().toString()));
		initialBlock.setPreviousHash("");
		initialBlock.setRandomSeed("");
		initialBlock.setWinningHash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
		blockChain.add(initialBlock);
	}

	public static Comparator<BlockRecord> BlockTSComparator = new Comparator<BlockRecord>() { // comparator for the priority queue. 
		@Override
		public int compare(BlockRecord b1, BlockRecord b2) {
			String s1 = b1.getTimeStamp();
			String s2 = b2.getTimeStamp();
			if (s1 == s2) {
				return 0;
			}
			if (s1 == null) {
				return -1;
			}
			if (s2 == null) {
				return 1;
			}
			return s1.compareTo(s2);
		}
	};

	class PublicKeyWorker extends Thread { // Public Key Server
		Socket sock; // Client Socket

		PublicKeyWorker(Socket s) {
			sock = s;
		} // Initialises the socket

		public void run() {

			BufferedReader fromProcess = null;
			try {
				fromProcess = new BufferedReader(new InputStreamReader(sock.getInputStream())); // Reads the public key from the process. 
				String publicKeyJSON = fromProcess.readLine(); 
				// Converting the key in JSON Format. 
				Type collectionType = new TypeToken<HashMap<String, String>>() {
				}.getType();
				HashMap<String, String> keyMap = new Gson().fromJson(publicKeyJSON, collectionType);
				publicKeys.putAll(keyMap);
				sock.close(); // closing the socket after results are found
			} catch (IOException ioe) {
				System.out.println(ioe);
			}
		}
	}

	class BlockChainWorker extends Thread {
		Socket sock; // Client Socket

		BlockChainWorker(Socket s) {
			sock = s;
		} // Initialises the socket

		public void run() {
			BufferedReader fromProcess = null;
			try {
				fromProcess = new BufferedReader(new InputStreamReader(sock.getInputStream())); // reads the block. 
				String blockChainJSON = fromProcess.readLine();
				Type collectionType = new TypeToken<ArrayList<BlockRecord>>() {
				}.getType();
				blockChain = new Gson().fromJson(blockChainJSON, collectionType); // converting it into JSON. 

				// if blockChain contains currentBlock id then mark block as already verified
				for (BlockRecord br : blockChain) {
					if (br.getBlockID().equals(currentBlock)) {
						alreadyVerified = true;
					}
				}
				if (pnum == 0) {
					BufferedWriter out;
					out = new BufferedWriter(new FileWriter("BlockchainLedger.json"));
					out.write(blockChainJSON); // writing the json to a file. 
					out.close();
					// save blockChainJSON to file
				}
				sock.close(); // closing the socket
			} catch (IOException ioe) {
				System.out.println(ioe);
			}
		}
	}

	class UnverifiedBlockWorker extends Thread { //Unverified Block Worker
		Socket sock;

		UnverifiedBlockWorker(Socket s) {
			sock = s;
		} // Initialises the socket

		public void run() {

			BufferedReader fromProcess = null;
			try {
				fromProcess = new BufferedReader(new InputStreamReader(sock.getInputStream())); 
				String unverifiedBlockJSON = fromProcess.readLine();
				Type collectionType = new TypeToken<BlockRecord>() { //Defining what type to convert from JSON. 
				}.getType();
				BlockRecord newUnverifiedBlock = new Gson().fromJson(unverifiedBlockJSON, collectionType);
				unverifiedQueue.add(newUnverifiedBlock); // adding the unverified block to the priority queue. 
				sock.close(); // closing the socket 
			} catch (IOException ioe) {
				System.out.println(ioe);
			}
		}
	}

	class Server implements Runnable {
		int portNum;

		Server(int portNum) { 
			this.portNum = portNum;
		}

		public void run() {

			int q_len = 2;
			Socket sock;
			Boolean run = true;

			try {
				ServerSocket servsock = new ServerSocket(portNum, q_len); // initialising a server socket for the given
																			// server.
				while (run) { // listen to connections as long as this is true.
					sock = servsock.accept(); // waiting for the connection.
					if (portNum < 4713) { // starting a new worker based on the port. 
						new PublicKeyWorker(sock).start(); 
					} else if (portNum < 4823) {
						new UnverifiedBlockWorker(sock).start(); 
					} else {
						new BlockChainWorker(sock).start(); 
					}
				}
				servsock.close();
			} catch (IOException ioe) {
				System.out.println(ioe);
			}

		}
	}

	class BlockVerifier implements Runnable { // Class for verifying unverified individual blocks 

		public void run() {
			outerloop: while (true) {
				BlockRecord blockToBeVerified;
				try {
					blockToBeVerified = unverifiedQueue.take(); // take the block from the priority queue. 
					BlockRecord verifiedBlock = new BlockRecord();
					do {
						// Check if its block id is already in blockchian
						for (BlockRecord br : blockChain) {
							if (br.getBlockID().equals(blockToBeVerified.getBlockID())) {
								// Abandon this block and verify new block from queue
								continue outerloop;
							}
						}
						// verify signed blockId instead of the data hash
						if (!verifyCont(blockToBeVerified.getBlockID(), blockToBeVerified.getSignedBlockID(),
								convertToPublicKey(publicKeys.get(blockToBeVerified.getCreationProcessID())))) {
							continue outerloop;
						}
						currentBlock = blockToBeVerified.getBlockID();
						verifiedBlock = mineBlock(blockToBeVerified, blockChain.get(blockChain.size() - 1));

						// Check if blockchain modified
					} while (verifiedBlock.getBlockNumber() <= blockChain.get(blockChain.size() - 1).getBlockNumber());
					blockChain.add(verifiedBlock);
					String blockchainJSON = new Gson().toJson(blockChain);

					// Multi cast blockchain to all processes
					for (int i = 0; i < 3; i++) {
						sendJSON(blockChainPort + i, blockchainJSON);
					}
				} catch (InterruptedException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (UnsupportedEncodingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (Exception e) {
					System.out.println("Block has already been verified");
				}
			}
		}
	}

	private static final String ranString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

	public static String randStrGenerate(int count) { // creating a random string for the data hash.
		StringBuilder b = new StringBuilder();
		while (count-- != 0) {
			int c = (int) (Math.random() * ranString.length());
			b.append(ranString.charAt(c));
		}
		return b.toString();
	}

	public static PublicKey convertToPublicKey(String key) { //convert the getPublicKey method data to publicKey format. 
		try {
			byte[] publicBytes = Base64.getDecoder().decode(key);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			return keyFactory.generatePublic(keySpec);
		} catch (InvalidKeySpecException e1) {
			e1.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public BlockRecord mineBlock(BlockRecord b, BlockRecord lastBlock)
			throws NoSuchAlgorithmException, UnsupportedEncodingException, Exception { //Method for mining a block and verifying it. 
		String previousHash = lastBlock.getWinningHash();
		int workNumber = 0;
		String hashString = "";
		String randomStr = "";
		do {
			if (alreadyVerified) { //if block is already verified by the other process skip and go to next one. nodes competing for verifying the blocks.
				alreadyVerified = false;
				currentBlock = "";
				throw new Exception();
			}
			try {
				Thread.sleep(2000);
			} catch (InterruptedException e) { // wait for sometime. 
			}
			randomStr = randStrGenerate(8);
			StringBuilder sb = generateHash(b, previousHash, randomStr);
			hashString = sb.toString();
			workNumber = Integer.parseInt(sb.substring(0, 4), 16); //worknumber is between the lowest 0 to highest 65k
		} while (workNumber > 20000); 
		b.setRandomSeed(randomStr);
		b.setPreviousHash(previousHash);
		b.setWinningHash(hashString);
		b.setVerificationProcessID(pnum.toString());
		b.setSignedWinningHash(signCont(hashString, privateKey));
		b.setBlockNumber(lastBlock.getBlockNumber() + 1);
		return b;
	}

	public static StringBuilder generateHash(BlockRecord b, String previousHash, String randomStr) //generating the hash value for a particular block.
			throws UnsupportedEncodingException, NoSuchAlgorithmException {
				// hash is generated using three fields, previous hash, data and random string. 
		String value = previousHash + b.getLname() + b.getFname() + b.getDOB() + b.getSSNum() + b.getDiag()
				+ b.getTreat() + b.getRx() + randomStr;
		MessageDigest md5 = MessageDigest.getInstance("SHA-256");
		// converting the hash into hexadecimal format. 
		byte[] array = md5.digest(value.getBytes("UTF-8"));
		StringBuilder b2s = new StringBuilder();
		for (int i = 0; i < array.length; ++i) {
			b2s.append(Integer.toHexString((array[i] & 0xFF) | 0x100).substring(1, 3));
		}
		return b2s;
	}

	public static String signCont(String text, PrivateKey privKey) throws Exception { // method for signing the hash or other data. 
		Signature privSig = Signature.getInstance("SHA256withRSA"); // signature class 
		privSig.initSign(privKey); // sign using the private key
		privSig.update(text.getBytes(UTF_8));
		byte[] pSArray = privSig.sign();
		//convert from byte to string. 
		return Base64.getEncoder().encodeToString(pSArray);
	}

	public static boolean verifyCont(String text, String sign, PublicKey pubKey) throws Exception { //method for verifying. 
		Signature pubSign = Signature.getInstance("SHA256withRSA"); //signature class
		pubSign.initVerify(pubKey); // verify using the public key
		pubSign.update(text.getBytes(UTF_8));
		byte[] signByteArray = Base64.getDecoder().decode(sign);
		return pubSign.verify(signByteArray);
	}

	public static PublicKey getPublicKeyFromString(String publicKey)
			throws InvalidKeySpecException, NoSuchAlgorithmException { //convert string Public key to PublicKeyFormat
		byte[] publicBytes = Base64.getDecoder().decode(publicKey);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
		KeyFactory keyFactory;
		PublicKey pk;
		keyFactory = KeyFactory.getInstance("RSA");
		pk = keyFactory.generatePublic(keySpec);
		return pk;
	}

	public static void sendJSON(int port, String json) {
		Socket sock;
		PrintStream toServer;
		try {
			sock = new Socket("localhost", port);
			toServer = new PrintStream(sock.getOutputStream());// writes to Server
			toServer.println(json);
			sock.close();
		} catch (IOException x) { // catches any I/O error
			System.out.println("Socket error.");
			x.printStackTrace();
		}
	}

	public static void startServers(int processNumber, Blockchain p) { // takes in the process Number and the Class Object as parameters to start three separate servers
		Server publicKeyServer = p.new Server(publicKeyPort + processNumber); //Public Key recieveing server. 
		Thread t = new Thread(publicKeyServer); // server starts at a new threads. 
		t.start(); //start the servers. 

		Server blockChainServer = p.new Server(blockChainPort + processNumber); //blockChain Server
		Thread t1 = new Thread(blockChainServer); // server starts at a new threads. 
		t1.start(); //start the servers. 

		Server unverifiedBlockServer = p.new Server(unverifiedBlockPort + processNumber); //unverified block
		Thread t2 = new Thread(unverifiedBlockServer);
		t2.start();

		BlockVerifier verifyQueue = p.new BlockVerifier(); // verifying queue server for the priority queue. 
		Thread t3 = new Thread(verifyQueue);
		t3.start();
	}

	public static String getPublicKeyJSON(String processNum) {
		KeyPairGenerator keyPairGen; // for generating public/private key pair. 
		String jsonPubKey = "";
		try {
			keyPairGen = KeyPairGenerator.getInstance("RSA"); //generates key in RSA format
			keyPairGen.initialize(1024); //set to 1024 bits
			KeyPair pair = keyPairGen.generateKeyPair(); //generate the pair
			privateKey = pair.getPrivate(); //saves the private key 
			PublicKey publicKey = pair.getPublic(); //saves the public key
			byte[] array = publicKey.getEncoded(); //converting into byte format
			String s = Base64.getEncoder().encodeToString(array); // converts byte to string 
			HashMap<String, String> map = new HashMap<>(); //saves the pair to the process number
			map.put(processNum, s);
			jsonPubKey = new Gson().toJson(map); //public key to json format
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return jsonPubKey;
	}

	public static ArrayList<String> readFile(String filename) { //method for reading the files for unverified blocks.
		String code = "";
		File file = new File(filename);
		Scanner fileReader;
		ArrayList<String> lineData = new ArrayList<String>();
		try {
			fileReader = new Scanner(file);
			while (fileReader.hasNextLine()) { // read the file line by line and print it.
				code = fileReader.nextLine();
				lineData.add(code);
			}
			fileReader.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		return lineData;
	}

	public static void processBlockInputs(Integer pnum) {
		String filename = "";

		switch (pnum) { // read the particular file according to the pnum. 
			case 1:
				filename = "BlockInput1.txt";
				break;
			case 2:
				filename = "BlockInput2.txt";
				break;
			default:
				filename = "BlockInput0.txt";
				break;
		}
		ArrayList<String> dataRecords = readFile(filename);
		for (int i = 0; i < dataRecords.size(); i++) {
			// try {
			// Thread.sleep(10000);
			// } catch (InterruptedException e) {

			// }
			try {
				String dataArray[] = dataRecords.get(i).split(" ");
				String fname = dataArray[0];
				String lname = dataArray[1];
				String bday = dataArray[2];
				String ssn = dataArray[3];
				String diag = dataArray[4];
				String treat = dataArray[5];
				String rX = dataArray[6];
				BlockRecord unverifiedBlock = new BlockRecord();
				unverifiedBlock.setFname(fname);
				unverifiedBlock.setLname(lname);
				unverifiedBlock.setDOB(bday);
				unverifiedBlock.setSSNum(ssn);
				unverifiedBlock.setDiag(diag);
				unverifiedBlock.setTreat(treat);
				unverifiedBlock.setRx(rX);
				unverifiedBlock.setCreationProcessID(pnum.toString());
				Date date = new Date();
				String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
				String TimeStampString = T1 + "." + pnum; // No timestamp collisions!
				String blockID = new String(UUID.randomUUID().toString());
				unverifiedBlock.setTimeStamp(TimeStampString); // Will be able to priority sort by TimeStamp
				unverifiedBlock.setBlockID(blockID);

				unverifiedBlock.setSignedBlockID(signCont(blockID, privateKey));

				String unverifiedBlockJSON = new Gson().toJson(unverifiedBlock);
				for (int j = 0; j < 3; j++) {
					sendJSON(unverifiedBlockPort + j, unverifiedBlockJSON);
				}
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	public static void main(String args[]) throws Exception {
		if (args.length < 1)		//Default process will be process 0
			pnum = 0;
		else if (args[0].equals("0")) //Assigning the process number thru the command args
			pnum = 0;
		else if (args[0].equals("1"))
			pnum = 1;
		else if (args[0].equals("2"))
			pnum = 2;
		else
			pnum = 0; 
		Blockchain p = new Blockchain(); 
		System.out.println("Starting Blockchain" + pnum + " Server");
		startServers(pnum, p); // starting individual servers for the nodes/process.

		// Delay
		try {
			Thread.sleep(10000);
		} catch (InterruptedException e) {

		}

		// Broadcast public key
		String publicKeyJSON = getPublicKeyJSON(args[0]);
		for (int i = 0; i < 3; i++) {
			sendJSON(publicKeyPort + i, publicKeyJSON); //Multicasting the public key of each process to other processes. 
		}
		try {
			Thread.sleep(5000);
		} catch (InterruptedException e) {

		}

		// Broadcast unverified blocks
		processBlockInputs(pnum);

		// Listen to inputs
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in)); // User Input is taken from the Server
		System.out.println();
		System.out.println("Enter command \n 'L' to Print BlockChain, \n 'V' to Verify BlockChain, \n 'C' to Print Verifying Credit, \n 'R' to read the block ");
		System.out.flush();
		while (true) { // Infinite loop to run the commands. 
			String inputCommand = in.readLine();
			if (inputCommand.equals("L")) { //Listing all the records with the other details. 
				for (int i = blockChain.size() - 1; i > 0; i--) {
					BlockRecord b = blockChain.get(i);
					System.out.println(b.getBlockNumber() + ": " + b.getTimeStamp() + " " + b.getFname() + " " +  b.getLname() + ": " + b.getDOB() + " " + b.getSSNum() + " " + b.getDiag() + " " + b.getRx());
				}	
			} else if (inputCommand.equals("V")) {
				Boolean isValid = true;
				for (int i = 1; i < blockChain.size(); i++) {
					BlockRecord b = blockChain.get(i);
					System.out.println("Verifying this Block: " + b.getBlockNumber());
					// verifying this block
					try { // verifying if the winning hash is equal to the randomstr + data + prevHash
						if (!b.getWinningHash().equals(generateHash(b, b.getPreviousHash(), b.getRandomSeed()).toString())) {
							System.out.println("Hash does not match data on " + b.getBlockNumber() + " Block, BlockChain is corrupted");
							isValid = false;
							break;
						}
					} catch (Exception e) {

					}

					if (!verifyCont(b.getWinningHash(), b.getSignedWinningHash(), //check if the signed hash is verified by the same public key which created it. 
							convertToPublicKey(publicKeys.get(b.getVerificationProcessID())))) {
							System.out.println("Failed to Verify Sign on " + b.getBlockNumber() + " Block, BlockChain is corrupted");
							isValid = false;
							break;
						}
				} 
				if (isValid){
					System.out.println("BlockChain is Valid");
				}
			} else if (inputCommand.equals("C")) { // List the number of blocks verified by each process. 
				int p0Count = 0;
				int p1Count = 0;
				int p2Count = 0;
				for (int i = 1; i < blockChain.size(); i++) { // creating counters for each process and incrementing each counter after it gets the verification id. 
					BlockRecord b = blockChain.get(i);
					if(b.getVerificationProcessID().equals("0")){
						p0Count++;
					} else if(b.getVerificationProcessID().equals("1")){
						p1Count++;
					} else if(b.getVerificationProcessID().equals("2")){
						p2Count++;
					}
				}
				System.out.println("Verification Report: " + "P0 = " + p0Count + " P1 = " + p1Count + " P2 = " + p2Count);
			}
		}
	}
}
