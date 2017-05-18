

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Scanner;
import java.security.SecureRandom;

public class ChangeByte {
/*
a. Prompt the user for the input file name
b. Open the file as a binary file
c. Prompt the user for which byte to change (i.e. you are indexing the file byte by byte)
d. Change the byte to a random value and close the file
*/

  public File file;
  public Scanner scanner;

  public static void main(String[] args){
    Scanner scanner = new Scanner(System.in);
    ChangeByte changeByte = new ChangeByte(scanner);
    changeByte.tamper();
  }

  public ChangeByte(Scanner scanner){
    this.scanner = scanner;
    setFile();
  }

  public ChangeByte(String filepath, Scanner scanner){
    this.scanner = scanner;
    setFile(filepath);
  }

  public void setFile(){
    do{
      System.out.println("Please enter a file path:");
      file = new File(scanner.nextLine());
    }while(!file.isFile());
  }

  public void setFile(String filepath){
    file = new File(filepath);
    while(!file.isFile()){
      System.out.println("Please enter a file path:");
      file = new File(scanner.nextLine());
    }
  }

  public void tamper(){
    int size = (int)file.length(); // gets the file size in bytes

    System.out.println("Please enter the byte index between 0 and " + size + " :");

    long index = validateLong(0, size); // gets user input

    // randomly chooses the new byte value
    SecureRandom rng = new SecureRandom();
    byte[] randomByte = new byte[1];
    rng.nextBytes(randomByte);

    // trys to access the file and change the selected index with the random value
    try {
        RandomAccessFile raf = new RandomAccessFile(file, "rw");
        raf.seek(index);
        raf.write(randomByte);
        raf.close(); // Flush/save changes and close resource.
    }
    catch(Exception e){
      System.out.println("Error: ChangeByte.tamper(...) Problem using RandomAccessFile");
    }
    System.out.println("Done!");
  }

  public long validateLong(long min, long max){
    long i = -1;
    do
    {
      i = scanner.nextLong();
      scanner.nextLine();
    }while( i < min || i > max);
    return i;
  }
}
