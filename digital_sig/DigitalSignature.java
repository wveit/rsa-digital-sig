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

/*
 * 			---- How to use DigitalSignature class ----
 * 
 * Basics:
 * 	+ DigitalSignature class provides static methods for:
 * 		- Creating a digital signature from an existing file
 * 		- Checking validity of a digital signature
 * 	+ Requires use of signer's public/private key pair (see RSAKey.java and KeyGen.java for more info about creating
 * 	  and using keys).
 * 		- Signer uses their private key to sign.
 * 		- Receiver uses signer's public key to verify signature
 * 
 * How to create a Digital Signature:
 * 		// Assume you are signing a file named "blah.txt" and that you have your private key 
 * 		// is in the file "myprivatekey.rsa"
 * 		RSAKey myPrivateKey = RSAKey.loadFromFile("myprivkey.rsa");
 * 		DigitalSignature.signFile("blah.txt", myPrivateKey);	// This creates a new file named "blah.txt.signed"
 * 																// that contains your digital signature.
 * 
 * How to verify a Digital Signature:
 * 		// Assume you are verifying a file named "blah.txt.signed" and that you have the signer's 
 * 		// public key in a file called "signerpublickey.rsa"
 * 		RSAKey signerPublicKey = RSAKey.loadFromFile("signerpublickey.rsa");
 * 		boolean isValid = DigitalSignature.verifySignature("blah.txt.signed", signerPublicKey);
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
