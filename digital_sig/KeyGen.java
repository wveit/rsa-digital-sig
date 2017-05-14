package digital_sig;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.Random;
import java.security.SecureRandom;

/*
 * 	-----  How to use KeyGen class -----
 * 
 * 	KeyGen objects are used in RSA public key cryptography to:
 * 		1. Hold keys or key pairs
 * 		2. Generate new keys
 * 		3. Save keys to file
 *  	4. Load keys from file
 *  
 *  To create a KeyGen object, just use no-arg constructor:
 *  	KeyGen keyGen = new KeyGen();
 *  
 *  Every KeyGen object has an e-component, a d-component, and an n-component, which are used in RSA public key
 *  	cryptography. 
 *  
 *  A KeyGen object can:
 *  	1. Hold just a private key - in this case the d-component and n-component are meaningful, but the e-component
 *  		is not (e-component will be zero).
 *  	2. Hold just a public key - in this case the e-component and n-component are meaningful, but the d-component
 *  		is not (d-component will be zero).
 *  	3. Hold the entire public/private key pair - in this case the d-component, e-component, and n-component are
 *  		all meaningful.
 *  	4. Hold no key - in this case all components are zero
 *  
 *  New KeyGen objects have an empty key set (i.e. the e, d, and n components are all zero)
 *  
 *  To generate a new RSA public/private key pair:
 *  	keyGen.generate();  // keyGen now contains the e, d, and n components of RSA key pair
 *  
 *  To access the e, d, and n components of a KeyGen object:
 *  	BigInteger e = keyGen.getE();
 *  	BigInteger d = keyGen.getD();
 *  	BigInteger n = keyGen.getN();
 *  
 *  KeyGen objects can load a private key from a file:
 *  	boolean success = keyGen.loadPrivateKey("myPrivateKey.rsa"); 
 *  	keyGen.getD(); // Returns whatever d-component value was stored in myPrivateKey.rsa
 *  	keyGen.getN(); // Returns whatever n-component value was stored in myPrivateKey.rsa
 *  	keyGen.getE(); // Returns zero, since e-component is not part of private key
 *  
 *  KeyGen objects can load a public key from a file:
 *  	boolean success = keyGen.loadPublicKey("myPublicKey.rsa");
 *  	keyGen.getE(); // Returns whatever e-component value was stored in myPublicKey.rsa
 *  	keyGen.getN(); // Returns whatever n-component value was stored in myPublicKey.rsa
 *  	keyGen.getD(); // Returns zero, since d-component is not part of public key
 *  	
 *  KeyGen that contain a private key or the public/private key pair can save private key to file
 *  	boolean success = keyGen.savePrivateKey("myPrivateKey.rsa"); // Saves only d and n components 
 *  																 // to myPrivateKey.rsa
 *  
 *  KeyGen that contain a public key or the public/private key pair can save public key to file
 *  	boolean success = keyGen.savePublicKey("myPublicKey.rsa"); // Saves only e and n components 
 *  															   // to myPublicKey.rsa
 *  
 *  !!! Warning !!! There is a danger, that someone may use a KeyGen object which is storing a private key to call 
 *  	public key methods. This can lead to incorrect results or program crash. Therefore it is important that the
 *  	programmer keep track of which type of key is being held by a KeyGen object before calling its methods. Here 
 *  	is example of danger code:
 *  
 *  	KeyGen keyGen = new KeyGen();
 *  
 *  	keyGen.loadPrivateKey("randomFile.txt"); // Problem #1, may not have successfully loaded but did not check 
 *  											 // return value. May not be able to trust contents.
 *  
 *  	keyGen.savePublicKey("newPublicKey.blah"); // Problem #2, keyGen contains private key, but we are trying to
 *  											   // save it as public key. A definite bug.
 *
 *		KeyGen myPublicKeyForTheWorldToSee = new KeyGen();
 *		myPublicKeyForTheWorldToSee.generate(); // Problem #3, this KeyGen object contains both public and private
 *												// key. DO NOT put this out for the world to see (if you plan to
 *												// actually use it for cryptography).
 * 
 * 		Check main() method for more examples of how to use 
 */
public class KeyGen {
	
	private Random rng = new SecureRandom();
	private BigInteger p = BigInteger.ZERO;
	private BigInteger q = BigInteger.ZERO;
	private BigInteger n = BigInteger.ZERO;
	private BigInteger totient = BigInteger.ZERO;
	private BigInteger e = BigInteger.ZERO;
	private BigInteger d = BigInteger.ZERO;
	
	public void generate(){
		p = new BigInteger(512, 100, rng);
		
		do{
			q = new BigInteger(512, 100, rng);
		}while(q.compareTo(p) == 0);
		 
		n = p.multiply(q);
		
		totient = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		
		do{
			e = new BigInteger(511, rng).setBit(512);
		}while(e.gcd(totient).compareTo(BigInteger.ONE) != 0);
		
		d = e.modInverse(totient);
	}
	
	public void print(){
		System.out.println();
		System.out.println("============================================================");
		System.out.println("  KeyGen contents");
		System.out.println("------------------------------------------------------------");
		System.out.println("p:  \t\t" + p);
		System.out.println("q:  \t\t" + q);
		System.out.println("n:  \t\t" + n);
		System.out.println("totient:  \t" + totient);
		System.out.println("e:  \t\t" + e);
		System.out.println("d:  \t\t" + d);
		System.out.println("============================================================");
		System.out.println();
	}
	
	public boolean savePublicKey(String filename){
		try{
			ObjectOutputStream out = new ObjectOutputStream( new FileOutputStream(filename) );
			
			out.writeObject(e);
			out.writeObject(n);
			
			out.close();
		}
		catch(Exception e){
			System.out.println("Error: KeyGen.savePublicKey(" + filename + ") could not save");
			return false;
		}
		
		return true;
	}
	
	public boolean savePrivateKey(String filename){
		try{
			ObjectOutputStream out = new ObjectOutputStream( new FileOutputStream(filename) );
			
			out.writeObject(d);
			out.writeObject(n);
			
			out.close();
		}
		catch(Exception e){
			System.out.println("Error: KeyGen.savePrivateKey(" + filename + ") could not save");
			return false;
		}
	
		return true;
	}
	
	public boolean loadPublicKey(String filename){
		try{
			ObjectInputStream in = new ObjectInputStream( new FileInputStream(filename) );
			
			e = (BigInteger)in.readObject();
			n = (BigInteger)in.readObject();
			d = BigInteger.ZERO;
			
			in.close();
		}
		catch(Exception e){
			System.out.println("Error: KeyGen.loadPublicKey(" + filename + ") could not load");
			return false;
		}
		
		return true;
	}
	
	public boolean loadPrivateKey(String filename){
		try{
			ObjectInputStream in = new ObjectInputStream( new FileInputStream(filename) );
			
			d = (BigInteger)in.readObject();
			n = (BigInteger)in.readObject();
			e = BigInteger.ZERO;
			
			in.close();
		}
		catch(Exception e){
			System.out.println("Error: KeyGen.loadPrivateKey(" + filename + ") could not load");
			return false;
		}
		
		return true;
	}
	
	public BigInteger getE(){
		return e;
	}
	
	public BigInteger getD(){
		return d;
	}
	
	public BigInteger getN(){
		return n;
	}
	
	
	
	public static void main(String[] args){
		KeyGen keygen = new KeyGen();
		keygen.generate();
		keygen.print();
		keygen.savePrivateKey("privkey.rsa");
		keygen.savePublicKey("pubkey.rsa");
		
		KeyGen privateKey = new KeyGen();
		privateKey.loadPrivateKey("privkey.rsa");
		KeyGen publicKey = new KeyGen();
		publicKey.loadPublicKey("pubkey.rsa");
		
		BigInteger notEncryptedInt = new BigInteger("230129347659230857156302986534088723687789834609809430985093489834029380498230498320948320");
		BigInteger encryptedInt = notEncryptedInt.modPow(privateKey.getD(), privateKey.getN());
		BigInteger decryptedInt = encryptedInt.modPow(publicKey.getE(), publicKey.getN());
		
		System.out.println("Before encryption: " + notEncryptedInt);
		System.out.println("After encryption:  " + encryptedInt);
		System.out.println("After decryption:  " + decryptedInt);
	}
	
	
}
