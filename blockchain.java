import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class blockchain {
    static final int D = 24;
    static final String block_1 = "aa0e5e8dcba8e27cc8c468aa27ce0bc674914d36b59287ea0571252fc0ae0146";
    static final String block_2 = "0000007286cc4640d42f890b6f02db7d1d08b13fefbb2d9642428a69a6892b9f";
    static final String block_3 = "0000001fafb4e548a16b22a7de87b0b958601fe327d2d5c9e57658660bb7886a";
    static final String block_4 = "000000373362645f89b0103fd905821b38419a41c225a7fa724fc5dcb3b2b777";
    static final String block_5 = "0000000200db173ba3a62db7e1691fc2cf0f0e3e4379b5ab029d1e769f1f8b65";
    static final String block_6 = "0000009b0c0b26ab271b4f603d43d85030b5a42e058b54eb11ef3d9933d81061";
    static final String block_7 = "00000046518fb7fe82d9820824a73b89d765960b59739fbee45089ed870160f6";
    static final String block_8 = "00000053d44819f7256458077ce6817463ccc7f23b0d667a3e154e5a0edeed59";
    static final String block_9 = "000000686785404caab6149b817bc0ab26faa8dcc46c36d132f48e9197e84754";
    static final String block_10 = "000000b8f91ddb481ad4a178ba7e93c0b7af8abc95700e92da24e386550b215d";

    static final String quote_1 = "The art of getting someone else to do something you want done because he wants to do it [Leadership]. -- Dwight D. Enseinhover.";
    static final String quote_2 = "I have never met a man so ignorant that I couldn't learn something from him. -- Galileo Galilei";
    static final String quote_3 = "Life moves pretty fast. If you don't stop and look around once in a while, you could miss it. -- Ferris Bueller";
    static final String quote_4 = "Within a computer natural language is unnatural. -- Alan J. Perlis (Epigrams in programming)";
    static final String quote_5 = "Bonne bosse et reste le boss. -- Darryl Amedon";
    static final String quote_6 = "In order to understand what another person is saying, you must assume that it is true and try to find out what it could be true of. -- George Miller";
    static final String quote_7 = "Within a computer natural language is unnatural. -- Alan J. Perlis (Epigrams in programming)";
    static final String quote_8 = "The hardest part of design ... is keeping features out. -- Donald Norman";
    static final String quote_9 = "To iterate is human, to recurse divine. -- L. Peter Deutsch";
    static final String quote_10 = "The best people and organizations have the attitude of wisdom: The courage to act on what they know right now and the humility to change course when they find better evidence. The quest for management magic and breakthrough ideas is overrated; being a master of the obvious is underrated. Jim Maloney is right: Work is an overrated activity -- Bob Sutton";


    public static void main(String[] args) throws NoSuchAlgorithmException {
        BigInteger nonce = BigInteger.ZERO;
        byte hash[];


        while (true) {
            nonce = nonce.add(BigInteger.ONE);

            byte tmp_array[] = combine_array(HexFormat.of().parseHex(block_10), check_sig(nonce.toByteArray()));

            hash = Hash(combine_array(tmp_array, quote_10.getBytes(StandardCharsets.US_ASCII)));

            if (hash[0] == 0 && hash[1] == 0 && hash[2] == 0) {
                break;
            }
        }
       
        System.out.println("nonce: " + nonce);
        System.out.println("\nhash: " + HexFormat.of().formatHex(hash));
    }

    public static byte[] Hash(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(input);
    }

    public static byte[] combine_array(byte[] x, byte[] y) {

        byte hash[] = new byte[x.length + y.length];
        System.arraycopy(x, 0, hash, 0, x.length);
        System.arraycopy(y, 0, hash, x.length, y.length);

        return hash;
    }

    public static byte[] check_sig(byte[] input) {
        if (input[0] == 0x00) {
            return Arrays.copyOfRange(input, 1, input.length);
        }
        return input;
    }
    
}
