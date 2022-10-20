import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.DSAKeyPairGenerator;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
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
            kpg.initialize(512);

            KeyPair kp = kpg.generateKeyPair();

            PrivateKey privateKey = kp.getPrivate();

//            Gunakan Abstract Class Signature untuk Create Signature Object
            Signature sign = Signature.getInstance("SHA1withDSA");

            sign.initSign(privateKey);
            sign.update((getHash(input)).getBytes());

//            System.out.println("Kunci Privat : "+kp.getPrivate());
//            System.out.println("Kunci Publik : "+kp.getPublic());
            System.out.println("Fungsi Hash : " + getHash(input));

            DSAPrivateKey privKey = (DSAPrivateKey) kp.getPrivate();
            DSAPublicKey pubKey = (DSAPublicKey) kp.getPublic();
            DSAParams dsap = privKey.getParams();

            System.out.println();
            System.out.println("Nilai P : " + dsap.getP());
            System.out.println("Nilai q : " + dsap.getQ());
            System.out.println("Nilai g : " + dsap.getG());
            System.out.println("Nilai x : " + privKey.getX());
            System.out.println("Nilai y : " + pubKey.getY());

//            BigInteger q = dsap.getQ();
//            BigInteger p = dsap.getP();
//            BigInteger g = dsap.getG();
//            BigInteger x = privKey.getX();
//            BigInteger y = pubKey.getY();




        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }
}