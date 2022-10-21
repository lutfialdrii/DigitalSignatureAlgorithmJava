import java.math.BigInteger;
import java.security.*;
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
        System.out.println("\n==================================================");
        System.out.println("======= Program Digital Signature Algorithm ======");
        System.out.println("==================================================");


        Scanner scn = new Scanner(System.in);
        System.out.print("\nMasukkan Message : ");

        String input = scn.next();
        System.out.println("\n==== Generate Fungsi Hash ====");
        System.out.println("Fungsi Hash : " + getHash(input));
        System.out.println("==============================");


        try {
            //Generate Public dan Private key
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
            //Generate angka secara acak
            SecureRandom secRan = new SecureRandom();
            kpg.initialize(512, secRan);

            // Instansiasi objek
            KeyPair kp = kpg.generateKeyPair();
            PrivateKey privateKey = kp.getPrivate();

            //Gunakan Abstract Class Signature untuk Create Signature Object
            Signature sign = Signature.getInstance("SHA1withDSA");

            // Instansiasi Objek
            DSAPrivateKey privKey = (DSAPrivateKey) kp.getPrivate();
            DSAPublicKey pubKey = (DSAPublicKey) kp.getPublic();
            DSAParams dsaParams = pubKey.getParams();

            System.out.println("\n=====  Parameter pada DSA ====");
            System.out.println("Nilai p : " + dsaParams.getP());
            System.out.println("Nilai q : " + dsaParams.getQ());
            System.out.println("Nilai g : " + dsaParams.getG());
            System.out.println("Nilai x : " + privKey.getX());
            System.out.println("Nilai y : " + pubKey.getY());
            System.out.println("===============================\n");

            /**
             * Step 1 : Membuat Digital Signature
             */

            System.out.println("==== Membuat Digital Signature ====");
            // Inisialisasi Tanda tangan menggunakan private key
            sign.initSign(privateKey);
            // Convert Hash to byte
            String hash1 = getHash(input);
            byte[] val1byte = getHash(input).getBytes();
            sign.update(val1byte);

            /*
            Metode sign() dari kelas java.security.Provider digunakan untuk
            mengembalikan byte tanda tangan dari semua data yang diperbarui.
            */
            byte[] signature = sign.sign();

            System.out.println("Digital Signature : "+signature);

            sign.update((getHash(input)).getBytes());

            System.out.println("Kunci Privat : " + privateKey);
//            System.out.println("Kunci Publik : "+ publicKey);
            System.out.println("Fungsi Hash : " + getHash(input));

            System.out.println("\n==== Mengirim Pesan ====>>>>>\n");



            /**
             * Step 2 : Verifikasi Digital Signature
             */
            System.out.println("\n==== Verifikasi Digital Signature ====");
            System.out.print("\nMasukkan Pesan yang diterima : ");
            String input2 = scn.next();

            String hash2 = getHash(input2);
            byte[] val2byte = getHash(input2).getBytes();

            // Inisiasi tanda tangan yang ada dengan mencocokkan Public Key
            sign.initVerify(kp.getPublic());
            sign.update(val2byte);

            if(hash1.equals(hash2) == true) {
                System.out.println("\nMessage Sama!");

                //Verifikasi Digital signature berdasarkan tanda tangan yang terdaftar
                System.out.println("Proses Verifikasi Digital Signature");
                boolean bool = sign.verify(signature);

                if(bool) {
                    System.out.println("\nOutput : Signature Terverifikasi");
                } else {
                    System.err.println("Signature Gagal");
                }
            } else {
                System.err.println("Message yang diterima Tidak Sama!");
            }


        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }
}