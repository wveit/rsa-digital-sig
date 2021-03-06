package digital_sig;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;
import java.util.Scanner;

public class Main {

	public static final String PROMPT =
		"Main Menu\n" +
		"1. Send massage\n" +
		"2. Receive message\n" +
		"3. Tamper message\n" +
		"4. Generate new keys\n" +
		"5. Show keys\n" +
		"6. Quit\n\n" +
		"Please enter the task number [1-6]: ";


	public static void main(String[] args){
		Scanner scanner = new Scanner(System.in);
		int input = 0;

		RSAKey[] keys = initKeys();

		RSAKey privateKey = keys[0];
		RSAKey publicKey = keys[1];

		while (input != 6){
			System.out.println(PROMPT);
			input = scanner.nextInt();
			scanner.nextLine();

			if (input == 1){
				send(scanner, privateKey);
			}

			else if (input == 2){
				receive(scanner, publicKey);
			}

			else if (input == 3){
				tamper(scanner);
			}

			else if (input == 4){
				keys = changeKeys();
				privateKey = keys[0];
				publicKey = keys[1];
			}

			else if (input == 5){
				showKeys(privateKey, publicKey);
			}

		}
		System.exit(0);
	}

	// index 0 is the privateKey, index 1 is the public key
	public static RSAKey[] initKeys(){
		RSAKey privateKey = RSAKey.loadFromFile("privkey.rsa");
		RSAKey publicKey = RSAKey.loadFromFile("pubkey.rsa");

		// If on key does not exist
		if(privateKey == null || publicKey == null){
			// make new keys
			KeyGen keygen = new KeyGen();
			keygen.generate();

			// save the keys
			keygen.getPrivateKey().saveToFile("privkey.rsa");
			keygen.getPublicKey().saveToFile("pubkey.rsa");

			// assign the keys
			privateKey = keygen.getPrivateKey();
			publicKey = keygen.getPublicKey();
		}

		// return the kyes as an array
		RSAKey[] keys = new RSAKey[2];
		keys[0] = privateKey;
		keys[1] = publicKey;
		return keys;
	}


	public static void send(Scanner scanner, RSAKey privateKey){
		
		System.out.println("Please enter a file to be signed:");
		File file = new File(scanner.nextLine());
		while(!file.isFile()){
			System.out.println("That file did not exist. Please enter a file to be signed:");
			file = new File(scanner.nextLine());
		}

		boolean success = DigitalSignature.signFile(file.getName(), privateKey);
		
		if(success){
			System.out.println();
			System.out.println(file.getName() + " has been signed. Created file: " + file.getName() + ".signed");
			System.out.println();
		}
		else{
			System.out.println();
			System.out.println("Error: could not sign " + file.getName());
			System.out.println();
		}
	}

	public static void receive(Scanner scanner, RSAKey publicKey){
		File signedMessage;
		String filepath = "";

		do{
			System.out.println("Please enter the name of a file to \"receive\" (should end with .signed):");
			filepath = scanner.nextLine();
			signedMessage = new File(filepath);
		}while(!signedMessage.isFile());


		if(!signedMessage.isFile()){
			System.out.println("The message has not been signed!");
			return;
		}

		boolean valid = DigitalSignature.verifySignature(signedMessage.getName(), publicKey);
		if(valid){
			System.out.println("It's Valid! Here's the message: ");
			System.out.println();

			byte[] messageBytes = DigitalSignature.extractMessageFromSignedFile(signedMessage.getName());
			if(messageBytes == null){
				System.out.println("Could not extract message");
			}
			else{
				String messageString = new String(messageBytes);
				System.out.println(messageString);
				System.out.println();
			}

		}
		else{
			System.out.println("It's not valid :(");
		}
	}

	public static void tamper(Scanner scanner){
		ChangeByte changeByte = new ChangeByte(scanner);
    changeByte.tamper();
	}

	public static RSAKey[] changeKeys(){
		KeyGen keygen = new KeyGen();
		keygen.generate();

		// save the keys
		keygen.getPrivateKey().saveToFile("privkey.rsa");
		keygen.getPublicKey().saveToFile("pubkey.rsa");

		// assign the keys
		RSAKey privateKey = keygen.getPrivateKey();
		RSAKey publicKey = keygen.getPublicKey();

		// return the keys as an array
		RSAKey[] keys = new RSAKey[2];
		keys[0] = privateKey;
		keys[1] = publicKey;
		return keys;
	}

	public static void showKeys(RSAKey privateKey, RSAKey publicKey){
		System.out.println("e: " + publicKey.getExponent());
		System.out.println("d: " + privateKey.getExponent());
		System.out.println("n: " + privateKey.getModulus());
	}

}
