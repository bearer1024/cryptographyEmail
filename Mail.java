import java.io.*;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

// class for encapsulating a mail
public class Mail implements Serializable {

	public String sender;
	public String recipient;
	public Date timestamp;
	public String message;
	public byte[] hashcash; // 4-byte array
	int count = 0;

	// constructor
	public Mail(String s, String r, String m) {
		sender = s;
		recipient = r;
		message = m;
		timestamp = new Date();
		hashcash = new byte[4]; // correct hashCash to be set separately
	}
	
	public void setHashcash(byte[] digest){
		this.hashcash = new byte[4];
		}
	
	public boolean checkHashcash(String recipient, Date timestamp, byte[] hashcash) throws NoSuchAlgorithmException{
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		md.update(this.recipient.getBytes());
        md.update(this.timestamp.toString().getBytes());
		md.update(this.hashcash);
		byte[] digest = md.digest();
		if (digest[0]==0 && digest[1] == 0){
			return true;
		}
		else{
			return false;
		}
	}

}
