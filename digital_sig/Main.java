package digital_sig;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;
import java.util.Scanner;

public class Main {

	public static final String PROMT =
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

		RSAKey[] keys = initKeys();;

		RSAKey privateKey = keys[0];
		RSAKey publicKey = keys[1];


		while (input != 6){
			System.out.println(PROMT);
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
		File file;
		do{
			System.out.println("Please enter a file path:");
			file = new File(scanner.nextLine());
		}while(!file.isFile());

		DigitalSignature.signFile(file.getName(), privateKey);
		System.out.println();
		System.out.println(file.getName() + " has been signed!");
	}

	public static void receive(Scanner scanner, RSAKey publicKey){
		File message;
		File signedMessage;
		String filepath = "";

		do{
			System.out.println("Please enter a file path (do not enter the .signedFile):");
			filepath = scanner.nextLine();
			message = new File(filepath);
		}while(!message.isFile());

		signedMessage = new File(filepath + ".signed");

		if(!signedMessage.isFile()){
			System.out.println("The message has not been signed!");
			return;
		}

		boolean valid = DigitalSignature.verifySignature(signedMessage.getName(), publicKey);
		if(valid){
			System.out.println("It's Valid! Here's the message: ");
			System.out.println();

			Path path = Paths.get(filepath);
			try (Stream<String> lines = Files.lines(path)) {
				lines.forEach(s -> System.out.println(s));
			} catch (Exception e) {
				System.out.println("An error has occured reading the file!");
			}
			System.out.println();

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

		// return the kyes as an array
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
