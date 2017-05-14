package digital_sig;

import java.io.EOFException;
import java.io.File;
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
import java.util.Scanner;

public class DigitalSignature {

	public static void main(String[] args){
		
		KeyGen privateKey = new KeyGen();
		privateKey.loadPrivateKey("privkey.rsa");
		signFile("message.txt", privateKey.getD(), privateKey.getN());
		
		KeyGen publicKey = new KeyGen();
		publicKey.loadPublicKey("pubkey.rsa");
		boolean valid = verifySignature("message.txt.signed", publicKey.getE(), publicKey.getN());
		if(valid)
			System.out.println("It's Valid!");
		else
			System.out.println("It's not valid :( ");
		
	}
	
	
	public static boolean signFile(String filename, BigInteger keyD, BigInteger keyN){
		
		byte[] messageByteArray = fileToByteArray(filename);
		if(messageByteArray == null){
			System.out.println("Error: could not find message file");
			return false;
		}
		
		
		String messageString = new String(messageByteArray);
		
		byte[] digestArray;
		
		try{
			MessageDigest md5Digestor = MessageDigest.getInstance("MD5");
			md5Digestor.update(messageByteArray);
			digestArray = md5Digestor.digest();
		}
		catch(NoSuchAlgorithmException e){
			System.out.println("Error: Could not digest message");
			return false;
		}
		
		
		BigInteger digest = new BigInteger(1, digestArray);
		System.out.println("Unencrypted Message:  " + digest);
		BigInteger signedDigest = digest.modPow(keyD, keyN);
		
		writeSignatureFile(filename + ".signed", signedDigest, messageString);
		
		return true;
		
	}
	
	

	
	public static boolean verifySignature(String filename, BigInteger keyE, BigInteger keyN){
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
		BigInteger decryptedDigestBigInt = signatureBigInt.modPow(keyE, keyN);
		System.out.println("Decrypted Digest:   " + decryptedDigestBigInt);
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
		System.out.println("Unencrypted digest2:   " + unencryptedDigestBigInt2);

		
		// Compare digest1 and digest 2
		if(digest1 == null || digest2 == null || digest1.length != digest2.length)
			return false;
		
		System.out.println("Digest1 length: " + digest1.length + "  Digest2 length: " + digest2.length);
		boolean valid = true;
		for(int i = 0; i < digest1.length; i++){
			System.out.println(digest1[i] + "  " + digest2[i]);
			if(digest1[i] != digest2[i]){
				valid = false;
			}
		}
		
		return valid;
	}
	
	public static boolean writeSignatureFile(String filename, BigInteger signedDigest, String originalMessage){
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
	
	public static byte[] fileToByteArray(String filename){
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
