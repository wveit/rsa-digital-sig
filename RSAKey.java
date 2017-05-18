

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

/*	========================================================================================================
 * 								---- How to use RSAKey class ----
 * 	========================================================================================================
 * 					
 * 
 *	Basics:
 * 		+ An RSAKey is used to encrypt or decrypt a message.
 * 			- A message is in the form of a BigInteger object of less than 1024 bits
 * 
 * 		+ RSA keys come in pairs: public key and private key.
 * 
 * 		+ Public/private key pairs are created together, using a KeyGen object.
 * 
 * 		+ If the private key encrypts a message, only its associated public key can decrypt it.
 * 
 * 		+ If the public key encrypts a message, only its associated private key can decrypt it.
 * 
 * 		+ Encryption and Decryption are basically the same operation (just using a different key). Therefore
 * 			the encrypt() method is used for both encryption and decryption.
 * 
 * 
 * 	How to get an RSA key object:
 * 		+ Keys must be created in pairs (public key and private key) to be useful. See the KeyGen class for how to 
 * 			create a key pair.
 * 
 * 		+ You can load a saved RSAKey from a file (see below).
 * 
 * 		+ The RSAKey constructor can also be used directly to create a key, but this is not usually the desired 
 * 			way to create it, since to be useful, keys need to be created as a pair.
 * 
 * 
 * 	How to encrypt/decrypt:
 * 		// Using publicKey to encrypt and privateKey to decrypt
 * 		BigInteger message = new BigInteger("40583298723094832049830");
 * 		BigInteger encryptedMessage = publicKey.encrypt(message);
 * 		BigInteger decryptedMessage = privateKey.encrypt(encryptedMessage);	// Even though we used the encrypt method,
 * 																			// we actually just decrypted the message.
 * 																			// message and decryptedMessage should be
 * 																			// the same.
 * 
 * 		// Or we could do this the other way around...
 *   	// Using privateKey to encrypt and publicKey to decrypt
 * 		BigInteger message = new BigInteger("40583298723094832049830");
 * 		BigInteger encryptedMessage = privateKey.encrypt(message);
 * 		BigInteger decryptedMessage = publicKey.encrypt(encryptedMessage);	// Even though this is the encrypt method,
 * 																			// we actually just decrypted the message.
 * 																			// message and decryptedMessage should be
 * 																			// the same.
 * 
 * 
 * 	How to save a key (or key pair) to file(s):
 * 		boolean success1 = publicKey.saveToFile("mypublickey.rsa");
 * 		boolean success2 = privateKey.saveToFile("myprivatekey.rsa");	// You cannot save both keys to the same file
 * 
 * 
 * 	How to load a key from file using the static loadFromFile() method:
 * 		RSAKey myPrivateKey = RSAKey.loadFromFile("myprivatekey.rsa");
 * 		RSAKey myPublicKey = RSAKey.loadFromFile("mypublickey.rsa");	// Be careful, this method will return null
 * 																		// if it was not successful (missing file,
 * 																		// wrong filename, corrupted data, etc). To
 * 																		// be safe, make sure to check if null was
 * 																		// returned.
 * 
 * 
 * 	See the KeyGen.java main() method for more examples on how to use the RSAKey class.
 * 
 */

public class RSAKey {
	private BigInteger exponent;
	private BigInteger modulus;
	
	public RSAKey(BigInteger exponent, BigInteger modulus){
		this.exponent = exponent;
		this.modulus = modulus;
	}
	
	public BigInteger encrypt(BigInteger message){
		return message.modPow(exponent, modulus);
	}
	
	public BigInteger getExponent(){
		return exponent;
	}
	
	public BigInteger getModulus(){
		return modulus;
	}
	
	public boolean saveToFile(String filename){
		try{
			ObjectOutputStream out = new ObjectOutputStream( new FileOutputStream(filename) );
			
			out.writeObject(exponent);
			out.writeObject(modulus);
			
			out.close();
		}
		catch(FileNotFoundException e){
			System.out.println("Error: RSAKey.saveToFile(" + filename + ") could not find file");
			return false;
		}
		catch(IOException e){
			System.out.println("Error: RSAKey.saveToFile(" + filename + ") could not save");
			return false;
		}
		
		return true;
	}
	
	public static RSAKey loadFromFile(String filename){
		BigInteger exponent = BigInteger.ZERO;
		BigInteger modulus = BigInteger.ZERO;
		
		try{
			ObjectInputStream in = new ObjectInputStream( new FileInputStream(filename) );
			
			exponent = (BigInteger)in.readObject();
			modulus = (BigInteger)in.readObject();
			
			in.close();
		}
		catch(FileNotFoundException e){
			System.out.println("Error: RSAKey.loadFromFile(" + filename + ") could not find file");
			return null;
		}
		catch(IOException e){
			System.out.println("Error: RSAKey.loadFromFile(" + filename + ") could not load");
			return null;
		}
		catch(ClassNotFoundException e){
			System.out.println("Error: RSAKey.loadFromFile(" + filename + ") could not load");
			return null;
		}
		
		return new RSAKey(exponent, modulus);
	}
}
