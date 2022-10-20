import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.DSAKeyPairGenerator;
import java.security.interfaces.DSAParams;
import java.util.Scanner;

public class Main {

    public static String getHash(String input) {
        try {

            //
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] messageDigest = md.digest(input.getBytes());

            BigInteger bigInteger = new BigInteger(1, messageDigest);

            // radix = 16, untuk convert kedalam HexaDecimal
            String hashText = bigInteger.toString(16);
            return hashText;


        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        String input = "Saya Mau Makan";
//        Scanner scn = new Scanner(System.in);
//        System.out.println("Masukkan Message : ");
//        input = scn.nextLine();
//        System.out.println("=== Generate Fungsi Hash ===");
//        System.out.println("Fungsi Hash : " + getHash(input));


        try {
            //Generate Public dan Private key
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
            kpg.initialize(1024);

            KeyPair kp = kpg.generateKeyPair();

            PrivateKey privateKey = kp.getPrivate();

//            Gunakan Abstract Class Signature untuk Create Signature Object
            Signature sign = Signature.getInstance("SHA1withDSA");

            sign.initSign(privateKey);
            sign.update((getHash(input)).getBytes());


        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }
}