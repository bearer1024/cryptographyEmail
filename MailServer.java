import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.*;
import java.security.*;

public class MailServer {

	public static void main(String[] args) throws Exception {

		System.out.println("Welcome...");
		int port = Integer.parseInt(args[0]);
		ServerSocket ss = new ServerSocket(port);

		HashMap<String, ArrayList<Mail>> allMailBoxes = new HashMap<String, ArrayList<Mail>>();

		while(true) {

			Socket s = ss.accept();
			DataOutputStream dos = new DataOutputStream(s.getOutputStream());
			DataInputStream dis = new DataInputStream(s.getInputStream());
			ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
			oos.flush(); // resolves hanging due to OIS constructor issue
			ObjectInputStream ois = new ObjectInputStream(s.getInputStream());

			// check login
			String clientId = dis.readUTF();
			if (!verifyLogin(dis, clientId)) { // failed to login
				System.out.println("Client " + clientId + " failed to log in.");
				dos.writeBoolean(false);
				continue;
			}

			System.out.println("Client " + clientId + " logged in.");
			dos.writeBoolean(true);

			// find mailbox for client
			if (!allMailBoxes.containsKey(clientId)) dos.writeInt(0);
			else {
				ArrayList<Mail> mailbox = (ArrayList<Mail>)allMailBoxes.get(clientId);
				dos.writeInt(mailbox.size());

				// send stored messages
				while(mailbox.size() > 0) {

					// message removed once sent
					oos.writeObject(mailbox.get(0));
					mailbox.remove(0);
				}
			}

			// receive message if this client wants to send
			if (dis.readBoolean()) {

				Mail m = (Mail)ois.readObject();

				// saves it
				ArrayList<Mail> mailbox;
				if (allMailBoxes.containsKey(m.recipient))
					mailbox = (ArrayList<Mail>)allMailBoxes.get(m.recipient);
				else
					mailbox = new ArrayList<Mail>();

				mailbox.add(m);
				allMailBoxes.put(m.recipient, mailbox);
				// replaces old entry in hashmap, if any

			}
			//ss.close();
			//s.close();

		}  // end while

	}  // end main

	public static boolean verifyLogin(DataInputStream dis, String userid) throws Exception {

		// TO DO
		
		// receive data and signature
        
        long t1 = dis.readLong();
        //double q1 = dis.readDouble();
        int length = dis.readInt();
        System.out.println("in the server,the length of signature is:"+length);
        byte[] signature = new byte[length];
        System.out.println("verifying for clientid is:"+userid);
        dis.readFully(signature);
        System.out.println("Server position2");
        
		// ByteBuffer to convert to bytes later
		ByteBuffer bb = ByteBuffer.allocate(16);
		bb.put(userid.getBytes());
		bb.putLong(t1);

		

        // should actually retrieve the appropriate key file using the received user name. For simplicity, hardcoded here
        String userPublicKeyFileName = userid + ".pub";
		ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(userPublicKeyFileName));
        PublicKey publicKey = (PublicKey)keyIn.readObject();
        keyIn.close();

        // verify signature
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(publicKey);
        sig.update(bb.array());
        
        // verify timeSpan
		// server local timeStamp
		long t2 = (new Date()).getTime();
		long timeSpan = t2 - t1;
		boolean timeFresh = false;
		if (timeSpan < 60000)
			timeFresh = true;
		
		//final check
        /*if (sig.verify(signature)&&timeFresh){
            System.out.println("Client logged in");
            return true;}
        else{
            System.out.println("Client failed to log in");
            return false;}*/
        if (sig.verify(signature)){
            System.out.println("signature is right");
            if(timeFresh){
               System.out.println("timespan is fresh");	
            }
            return true;}
        else{
            System.out.println("Client failed to log in");
            return false;}
		 
	}

}  // end class
