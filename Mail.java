import java.io.*;
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
		hashcash = new byte[4]; // correct hashcash to be set separately
	}
	
	public void setHashcash(byte[] digest){
		this.hashcash = new byte[4];
		
		
		//this.hashcash += ;
	}
	public boolean checkHashcash(byte[] digest){
		if (digest[0]==0 && digest[1] == 0)
			return true;
		else return false;
	}

}
