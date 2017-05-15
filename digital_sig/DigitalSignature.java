package digital_sig;

import java.io.EOFException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;


/*	========================================================================================================
 * 								---- How to use DigitalSignature class ----
 * 	========================================================================================================
 * 
 *	Basics:
 *		+ Let's say Alice wants to send Bob a message in a way that Bob can be sure it is from her and that it has not 
 * 			been tampered with. She can do this by creating a digital signature for the message using her private key,
 * 			and then sending the digital signature and message together to Bob. 
 * 
 *  	+ When Bob receives the digital signature and message, he can use the digital signature and Alice's public key
 *  		to verify that the message really did come from Alice, and that the message has not been tampered with.
 *  
 *  	+ In the above exchange, Alice would be called the Sender, and Bob would be called the Receiver
 *  
 *  	+ The DigitalSignature class provides two static methods that allow a sender and receiver to exchange a message
 *  		like Alice and Bob just did.
 *  
 *  
 *  How a Sender can send a message and digital signature to the Receiver:
 *  	// Assume I am the sender (Alice).
 *  	// Assume my message is in a file called "blah.txt"
 *  	// Assume my private key is in a file called "aliceprivatekey.rsa"
 *  
 *  	RSAKey alicePrivateKey = RSAKey.loadFromFile("aliceprivatekey.rsa");
 *  	boolean success = DigitalSignature.signFile("blah.txt", alicePrivateKey);
 *  
 *  	// If success == true, we know that the signFile() method just created a new file named "blah.txt.signed"
 *  	//	that contains a digital signature and the original message.
 *  	// "blah.txt.signed" can now be sent to the Receiver (Bob)
 * 
 * 
 * 	How a Receiver of a .signed file can verify that the digital signature and message match:
 * 		// Assume I am the receiver (Bob)
 * 		// Assume that the sender (Alice) sent me the file "blah.txt.signed" which I know contains a digital
 * 		//		signature followed by a message
 * 		// Assume that I have the Sender's public key in the file "alicepublickey.rsa"
 * 
 * 		RSAKey alicePublicKey = RSAKey.loadFromFile("alicepublickey.rsa");
 * 		boolean success = DigitalSignature.verifySignature("blah.txt.signed", alicePublicKey);
 * 
 * 		// If success == true, we know that:
 * 		// 		* The file "blah.txt.signed" does in fact contain a digital signature followed by a message
 * 		//		* The digital signature was created with the Sender's private key, for the contained message
 * 		//		* The message and digital signature have not been tampered with
 * 
 * 	
 * 		
 */

public class DigitalSignature {

	public static void main(String[] args){

		RSAKey privateKey = RSAKey.loadFromFile("privkey.rsa");
		signFile("message.txt", privateKey);

		RSAKey publicKey = RSAKey.loadFromFile("pubkey.rsa");
		boolean valid = verifySignature("message.txt.signed", publicKey);
		if(valid)
			System.out.println("It's Valid!");
		else
			System.out.println("It's not valid :( ");

	}


	public static boolean signFile(String filename, RSAKey privateKey){

		byte[] messageByteArray = fileToByteArray(filename);
		if(messageByteArray == null){
			System.out.println("Error: DigitalSignature.signFile(...) could not find/read file");
			return false;
		}


		String messageString = new String(messageByteArray);

		byte[] digestArray;

		try{
			MessageDigest digestor = MessageDigest.getInstance("MD5");
			digestor.update(messageByteArray);
			digestArray = digestor.digest();
		}
		catch(NoSuchAlgorithmException e){
			System.out.println("Error: DigitalSignature.signFile(...) Problem using MD5 Message Digest");
			return false;
		}


		BigInteger digest = new BigInteger(1, digestArray);
		//System.out.println("Unencrypted Digest Before Signing:  " + digest);
		BigInteger signedDigest = privateKey.encrypt(digest);

		if(!writeSignatureFile(filename + ".signed", signedDigest, messageString)){
			System.out.println("Error: DigitalSignature.signFile(...) Could not write .signed file");
			return false;
		}

		return true;
	}




	public static boolean verifySignature(String filename, RSAKey publicKey){
		// !! Attention.. This method works correctly but needs updates !!
		//		1) close ObjectInputStream after use
		//		2) fill in exception handling sections


		// Get BigInteger and byte array from signature file
		BigInteger signatureBigInt = BigInteger.ONE;
		ArrayList<Byte> byteArrayList = new ArrayList<>();;
		byte[] messageByteArray = null;

		try{
			FileInputStream fin = new FileInputStream(filename);
			ObjectInputStream objectIn = new ObjectInputStream(fin);

			signatureBigInt = (BigInteger)objectIn.readObject();

			while(true){
				byteArrayList.add(objectIn.readByte());
			}

		}
		catch(EOFException e){
			// This exception is expected when finished reading file
			messageByteArray = new byte[byteArrayList.size()];
			for(int i = 0; i < byteArrayList.size(); i++){
				messageByteArray[i] = byteArrayList.get(i);
			}
		}
		catch(FileNotFoundException e){

		}
		catch(IOException e){

		}
		catch(ClassNotFoundException e){

		}


		// Convert BigInteger into unencrypted digest (digest1)
		BigInteger decryptedDigestBigInt = publicKey.encrypt(signatureBigInt);
		//System.out.println("Decrypted Digest:   " + decryptedDigestBigInt);
		byte[] digest1 = decryptedDigestBigInt.toByteArray();

		// Convert byte array into unencrypted digest (digest2)
		byte[] digest2 = null;
		try{
			MessageDigest md5Digestor = MessageDigest.getInstance("MD5");
			md5Digestor.update(messageByteArray);
			digest2 = md5Digestor.digest();
		}
		catch(NoSuchAlgorithmException e){
			return false;
		}

		BigInteger unencryptedDigestBigInt2 = new BigInteger(digest2);
		//System.out.println("Unencrypted digest2:   " + unencryptedDigestBigInt2);


		// Compare digest1 and digest 2
		if(digest1 == null || digest2 == null || digest1.length != digest2.length)
			return false;

		//System.out.println("Digest1 length: " + digest1.length + "  Digest2 length: " + digest2.length);
		boolean valid = true;
		for(int i = 0; i < digest1.length; i++){
			//System.out.println(digest1[i] + "  " + digest2[i]);
			if(digest1[i] != digest2[i]){
				valid = false;
			}
		}

		return valid;
	}

	private static boolean writeSignatureFile(String filename, BigInteger signedDigest, String originalMessage){
		try{
			FileOutputStream fout = new FileOutputStream(filename);
			ObjectOutputStream objectOut = new ObjectOutputStream(fout);

			objectOut.writeObject(signedDigest);
			objectOut.write(originalMessage.getBytes());

			objectOut.close();
		}
		catch(FileNotFoundException e){
			return false;
		}
		catch(IOException e){
			return false;
		}

		return true;
	}

	private static byte[] fileToByteArray(String filename){
		ArrayList<Byte> byteArrayList = new ArrayList<>();

		try{
			FileInputStream fin = new FileInputStream(filename);

			int inputInt = fin.read();
			while(inputInt >= 0){
				byte b = (byte) inputInt;
				byteArrayList.add(b);

				inputInt = fin.read();
			}
			fin.close();
		}
		catch(FileNotFoundException e){
			return null;
		}
		catch(IOException e){
			return null;
		}

		byte[] byteArray = new byte[byteArrayList.size()];
		for(int i = 0; i < byteArrayList.size(); i++){
			byteArray[i] = (byte)byteArrayList.get(i);
		}

		return byteArray;
	}

}
