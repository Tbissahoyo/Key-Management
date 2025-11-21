
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class blockchain {
    static final SecureRandom SRand = new SecureRandom();
    static final int D = 24;
    static final String block_1 = "133e103b159f199f581db507ca7276dbc8eb25c9b76a008253cc946b165ad74d";
    static final String block_2 = "00000014eb5f46ae7b48550ca47b47b6881516b0c38130a1b6ba1ca8e4451051";
    static final String block_3 = "000000c9814659069f4bef12930924b79fcc8a480d01fca4df12a6bca038ea6f";
    static final String block_4 = "000000e50eb1bf0423c7904c4d8d85d8ff9bb47bac424521cbdbdc7d69f88765";
    static final String block_5 = "000000a3f138511219ec0d5e0724fac3daa44c48e269ad131eca0eea21a7f0db";
    static final String block_6 = "0000005e0febcf127ad26049b8218d75c9904f58f3c279101ed77907989699ba";
    static final String block_7 = "00000058b2c399fae628da08961e4e39ac3223fc7adb35fecccd5d531db37e26";
    static final String block_8 = "00000038d5c03efac9b342bf231ba2a162a85cf6082a2cbdb3cc27c38cadfc9a";
    static final String block_9 = "";
    static final String block_10 = "";

    static final String quote_1 = "Remember that you are humans in the first place and only after that programmers. -- Alexandru Vancea";
    static final String quote_2 = "The trouble with the world is that the stupid are always cocksure and the intelligent are always filled with doubt. -- Bertrand Russell";
    static final String quote_3 = "But what is it good for? -- Engineer at the Advanced Computing Systems Division of IBM, commenting on the microchip, 1968";
    static final String quote_4 = "Functional programming is like describing your problem to a mathematician. Imperative programming is like giving instructions to an idiot. -- arcus, #scheme on Freenode";
    static final String quote_5 = "I was talking recently to a friend who teaches at MIT. His field is hot now and every year he is inundated by applications from would-be graduate students. \"A lot of them seem smart,\" he said. \"What I can't tell is whether they have any kind of taste.\" -- Paul Graham";
    static final String quote_6 = "We now come to the decisive step of mathematical abstraction: we forget about what the symbols stand for. ...[The mathematician] need not be idle; there are many operations which he may carry out with these symbols, without ever having to look at the things they stand for. -- Hermann Weyl, The Mathematical Way of Thinking";
    static final String quote_7 = "The purpose of abstraction is not to be vague, but to create a new semantic level in which one can be absolutely precise. -- Edsger Dijkstra";
    static final String quote_8 = "Saying that Java is nice because it works on all OSes is like saying that anal sex is nice because it works on all genders. -- Alanna";
    static final String quote_9 = "";
    static final String quote_10 = "";


    public static void main(String[] args) throws NoSuchAlgorithmException {
        BigInteger tmp = BigInteger.ZERO;
        byte hash[];

        while (true) {
            tmp = tmp.add(BigInteger.ONE);

            byte tmp_array[] = combine_array(HexFormat.of().parseHex(block_8), tmp.toByteArray());

            hash = Hash(combine_array(tmp_array, quote_8.getBytes(StandardCharsets.US_ASCII)));

            if (hash[0] == 0 && hash[1] == 0 && hash[2] == 0) {
                break;
            }
        }
       
        System.out.println("nonce: " + tmp);
        System.out.println("\nhash: " + HexFormat.of().formatHex(hash));
    }

    public static byte[] Hash(byte[] input) throws NoSuchAlgorithmException {
        //turn plaintext and hex into byte array 
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(input);
    }

    public static byte[] combine_array(byte[] x, byte[] y) {

        byte hash[] = new byte[x.length + y.length];
        System.arraycopy(x, 0, hash, 0, x.length);
        System.arraycopy(y, 0, hash, x.length, y.length);

        return hash;
    }    
}
