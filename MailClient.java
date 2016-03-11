import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.*;
import java.security.*;

public class MailClient {

	public String getMessage(Mail m) {
		return m.message;
	}

	public static void main(String[] args) throws Exception {

		// Initialisation
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

		String host = args[0];
		int port = Integer.parseInt(args[1]);
		String userid = args[2];

		// connect to server
		Socket s = new Socket(host, port);
		DataInputStream dis = new DataInputStream(s.getInputStream());
		DataOutputStream dos = new DataOutputStream(s.getOutputStream());
		ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
		oos.flush();
		ObjectInputStream ois = new ObjectInputStream(s.getInputStream());

		// TO DO: login
		
		dos.writeUTF(userid);

		String userPrivateKeyFileName = userid + ".prv";
		// Get the key to create the signature
		ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(
				userPrivateKeyFileName));
		PrivateKey privateKey = (PrivateKey) keyIn.readObject();
		keyIn.close();

		// create timeStamp and random number
		long t1 = (new Date()).getTime();
		// ByteBuffer to convert to bytes later
		ByteBuffer bb = ByteBuffer.allocate(16);
		bb.put(userid.getBytes());
		bb.putLong(t1);

		// create signature, using timeStamp and random number as data
		Signature sig = Signature.getInstance("SHA1withRSA");
		sig.initSign(privateKey);
		sig.update(bb.array());
		byte[] signature = sig.sign();

		// send data and signature
		dos.writeLong(t1);
		dos.writeInt(signature.length);
		System.out.println("in the client,the length of signature is :"
				+ signature.length);
		dos.write(signature);
		dos.flush();

		boolean answer = dis.readBoolean();

		System.out.println("You have logged in now");
		// passed the verifyLogin
		if (answer) {
			// receive how many messages
			int numMsg = dis.readInt();
			System.out.println("You have " + numMsg + " incoming messages.");

			// TO DO: read messages
			ArrayList<Mail> msg = new ArrayList<Mail>(numMsg);
			for (int i = 0; i < numMsg; i++) {
				Mail ma = (Mail) ois.readObject();

				// for each mail, display sender,timeStamp,message
				System.out.println(ma.sender);
				System.out.println(ma.timestamp);
				System.out.println(ma.message);

				ByteBuffer bf1 = ByteBuffer.allocate(8);
				bf1.putLong(ma.timestamp.getTime());
				MessageDigest md = MessageDigest.getInstance("SHA-1");
				md.update(ma.recipient.getBytes());
				md.update(bf1.array());
				md.update(ma.hashcash);

				byte[] digest = md.digest();
				boolean normalMail = ma.checkHashcash(ma.recipient,
						ma.timestamp, ma.hashcash);
				if (normalMail) {
					// check each mail is belongs to SPAM or not
					// show message
					System.out.println("it's a normal message.");
					System.out.println(ma.message);
				} else {
					System.out.println(digest[0]);
					System.out.println(digest[1]);
					System.out.println("it's a spam message.");
					System.out.println(ma.message);
				}
			}
		}

		// send messages
		System.out.println("Do you want to send a message [Y/N]?");
		String wantToSend = br.readLine();
		if (!wantToSend.equals("Y")) {
			if(!wantToSend.equalsIgnoreCase("y")){
			dos.writeBoolean(false);
			return;
			}
		}
		dos.writeBoolean(true);

		System.out.println("Enter userid of recipient:");
		String recipient = br.readLine();
		System.out.println("Type your message:");
		String message = br.readLine();

		// TO DO: send mail
		Mail m = new Mail(userid, recipient, message);

		while (true) {
			Random r = new Random();
			int hash = r.nextInt();
			ByteBuffer b = ByteBuffer.allocate(16);
			b.putInt(hash);
			byte[] hashcash = b.array();
			m.hashcash = hashcash;
			if (m.checkHashcash(m.recipient, m.timestamp, m.hashcash)) {
				break;
			} else {

				continue;
			}

		}
		System.out.println("digest[0] and digest[1] is equal now");

		oos.writeObject(m);
	}

}
