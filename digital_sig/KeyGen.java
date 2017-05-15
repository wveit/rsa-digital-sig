package digital_sig;

import java.math.BigInteger;
import java.util.Random;
import java.security.SecureRandom;

/*	========================================================================================================
 * 								---- How to use KeyGen class ----
 * 	========================================================================================================
 * 				
 * 	Basics:
 * 		+ KeyGen objects are used to create public/private key pairs for RSA public key encryption.
 * 
 * 		+ For information about how to use RSAKey objects, see instructions in RSAKey.java
 * 
 * 
 * 	How to create a Key Generator:
 * 		KeyGen keyGen = new KeyGen();
 * 
 * 
 * 	How to generate a new public/private key pair:
 * 		keyGen.generate();
 * 
 * 
 * 	How to get the generated keys from a KeyGen object after calling generate() method:
 * 		RSAKey publicKey = keyGen.getPublicKey();
 * 		RSAKey privateKey = keyGen.getPrivateKey();
 * 
 * 
 * 	A KeyGen object generate() method is called, it will remember the generated key pair until generate() is called
 * 		again.
 * 
 * 
 * 	A KeyGen object also remembers the data associated with creating those keys (p, q, n, totient, e, d). To
 * 	print out this data:
 * 		keyGen.print();
 * 
 * 
 * 	See the main() method for more examples of how to use a key generator and the keys it generates.
 *
 */
public class KeyGen {

	private Random rng = new SecureRandom();

	private BigInteger p = BigInteger.ZERO;
	private BigInteger q = BigInteger.ZERO;
	private BigInteger n = BigInteger.ZERO;
	private BigInteger totient = BigInteger.ZERO;
	private BigInteger e = BigInteger.ZERO;
	private BigInteger d = BigInteger.ZERO;

	private RSAKey privateKey = new RSAKey(BigInteger.ZERO, BigInteger.ZERO);
	private RSAKey publicKey = new RSAKey(BigInteger.ZERO, BigInteger.ZERO);

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

		privateKey = new RSAKey(d, n);
		publicKey = new RSAKey(e, n);
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

	public RSAKey getPrivateKey(){
		return privateKey;
	}

	public RSAKey getPublicKey(){
		return publicKey;
	}


	public static void main(String[] args){
		KeyGen keygen = new KeyGen();
		keygen.generate();
		keygen.print();

		keygen.getPrivateKey().saveToFile("privkey.rsa");
		keygen.getPublicKey().saveToFile("pubkey.rsa");

		RSAKey privateKey = RSAKey.loadFromFile("privkey.rsa");
		RSAKey publicKey = RSAKey.loadFromFile("pubkey.rsa");

		BigInteger originalMessage = new BigInteger("23012934765923085715630298653408872368778");
		BigInteger encryptedMessage = privateKey.encrypt(originalMessage);
		BigInteger decryptedMessage = publicKey.encrypt(encryptedMessage);

		System.out.println("Original Message:      " + originalMessage);
		System.out.println("Encrypted Message:     " + encryptedMessage);
		System.out.println("Decrypted Message:     " + decryptedMessage);
	}
}
