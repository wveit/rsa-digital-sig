package digital_sig;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.Random;
import java.security.SecureRandom;

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
		
		keygen = new KeyGen();
		keygen.loadPrivateKey("privkey.rsa");
		keygen.print();
	}
	
	
}
