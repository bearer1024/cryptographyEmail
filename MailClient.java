import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.*;
import java.security.*;

public class MailClient {
	
	public String getMessage(Mail m){
		return m.message;
	}

	public static void main(String[] args) throws Exception {

		// Initialisation
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

		String host = args[0];
		int port = Integer.parseInt(args[1]);
		String userid = args[2];
		
		
			// connect to server
			Socket s = new Socket(host,port);
			DataInputStream dis = new DataInputStream(s.getInputStream());
			DataOutputStream dos = new DataOutputStream(s.getOutputStream());
			ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
			oos.flush();
			ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
	
			// TO DO: login
	
			// these two lines are here just to make the supplied programs run without crashing.
			// You may want to change them, and certainly add things after them
			dos.writeUTF(userid);
	
			String userPrivateKeyFileName = userid + ".prv";
			// Get the key to create the signature
	        ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(userPrivateKeyFileName));
	        PrivateKey privateKey = (PrivateKey)keyIn.readObject();
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
	        System.out.println("in the client,the length of signature is :"+signature.length);
	        dos.write(signature);
	        dos.flush();

			boolean answer = dis.readBoolean();
			
			System.out.println("You have logged in now");
			//passed the verifyLogin
			if (answer)
				{
				// receive how many messages
				int numMsg = dis.readInt();
				System.out.println("You have " + numMsg + " incoming messages.");
		
				// TO DO: read messages
				ArrayList<Mail> msg = new ArrayList<Mail>(numMsg);
				for(int i=0;i<numMsg;i++){
					//@Unchecked
					//msg = (Mail) ois.readObject();
					Mail ma = (Mail) ois.readObject();
					
						System.out.println("position4");
						//for each mail, display sender,timeStamp,message
						System.out.println(ma.sender);
						System.out.println(ma.timestamp);
						System.out.println(ma.message);
						MessageDigest md = MessageDigest.getInstance("SHA-1");
						md.update(msg.get(0).hashcash);
						
						byte[] digest = md.digest();
						boolean normalMail = msg.get(0).checkHashcash(digest);
						if(normalMail){
						//check each mail is belongs to SPAM or not
						//receive mail
							System.out.println(msg.get(0).message);
							}
						else{System.out.println("it's a spam message.");
							System.out.println(msg.get(0).message);
							}
						msg.remove(0);
					}
				}
				/*while(!msg.isEmpty()){
					System.out.println("position4");
					//for each mail, display sender,timeStamp,message
					System.out.println(msg.get(0).sender);
					System.out.println(msg.get(0).timestamp);
					System.out.println(msg.get(0).message);
					MessageDigest md = MessageDigest.getInstance("SHA-1");
					md.update(msg.get(0).hashcash);
					
					byte[] digest = md.digest();
					boolean normalMail = msg.get(0).checkHashcash(digest);
					if(normalMail){
					//check each mail is belongs to SPAM or not
					//receive mail
						System.out.println(msg.get(0).message);
						}
					else{System.out.println("it's a spam message.");
						System.out.println(msg.get(0).message);
						}
					msg.remove(0);
				}*/
	
				
				// send messages
				System.out.println("Do you want to send a message [Y/N]?");
				String wantToSend = br.readLine();
				if (!wantToSend.equals("Y")) {
					dos.writeBoolean(false);
					return ;
				}
				dos.writeBoolean(true);
		
				System.out.println("Enter userid of recipient:");
				String recipient = br.readLine();
				System.out.println("Type your message:");
				String message = br.readLine();
				
		
				// TO DO: send mail
		        ByteBuffer bf = ByteBuffer.allocate(8);
				Mail m = new Mail(userid, recipient, message);
				//create digest
				bf.putLong(m.timestamp.getTime());//store sender's timeStamp
				
				MessageDigest md = MessageDigest.getInstance("SHA-1");
				md.update(m.recipient.getBytes());
				md.update(bf.array());
				md.update(m.hashcash);
				byte[] digest = md.digest();
				
				while(!m.checkHashcash(digest)){
					m.setHashcash(digest);
					break;
					
				}
				System.out.println("digest[0] is equal now");
				/*dos.write(digest);
				dos.flush();
				// send timeStamp and digest to server
				long mailTimestamp = m.timestamp.getTime();
				dos.writeLong(mailTimestamp);*/

				oos.writeObject(m);
				
				}
			else{
				System.out.println("failed to login");
			}
			
			

	}

}
