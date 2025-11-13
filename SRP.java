import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SRP {
    static final SecureRandom rand = new SecureRandom();
    static final BigInteger two = BigInteger.valueOf(2);
    static final BigInteger one = BigInteger.ONE;
    static final BigInteger zero = BigInteger.ZERO;
    static final BigInteger neg_one = BigInteger.valueOf(-1);
    static final int len = 1035;
    static final int iterations = 1000;
    static final BigInteger g = new BigInteger("5");
    static final BigInteger p = new BigInteger(
            "233000556327543348946447470779219175150430130236907257523476085501968599658761371268535640963004707302492862642690597042148035540759198167263992070601617519279204228564031769469422146187139698860509698350226540759311033166697559129871348428777658832731699421786638279199926610332604408923157248859637890960407");


    static final BigInteger pub_key_g_a = new BigInteger(
            "31933325037680578067915788684848799884239892161631574599718562003089937928976936269997554492073437566954181371230079463382827683165191661731020097070507152206300885877045692139968468603205418370532614833022885793819159147108533314655900701984334164070256048651342963965714302292760638407276465399494719581324"); //
    static final BigInteger B = new BigInteger("33419549738735808993322273321541392370999450987991442032778945508034485195792919953432048983074883818376429260408131935881742078775650994904128858828296264414011801677798234366553124272239362855955590607215377763818258742590070225758739757932780118242818095006321076336738684475213000187542384230505078617694");
    
    
    public static void main(String[] args) throws Exception {
        String password = "intentionless";
        String salt = "0ce7790d";
        String username = "tbissaho";

        //generate a
        // BigInteger a = new BigInteger(len / 3, rand);
        BigInteger a = new BigInteger(
                "1593833105236885813434905301954329369442171637278971377314463913297026854485718642102281211305417618642");
        
        // System.out.println("a: " + a);
        BigInteger g_a = Fast_modular_exp(a, g, p); //pubkey
        System.out.println("\ng_a: " + g_a);

        //hash of salt || password

        byte salt_array[] = HexFormat.of().parseHex(salt);
        byte password_array[] = password.getBytes(StandardCharsets.UTF_8);
        byte combine_array[] = combine_array(salt_array, password_array);

        for (int i = 0; i < 1000; i++){
            combine_array = Hash(combine_array);
        }

        BigInteger x = new BigInteger(1,combine_array);
        System.out.println("Password hash: " + x);

        //calculating k
        BigInteger k = new BigInteger(1, Hash(combine_array(check_sig(p.toByteArray()), check_sig(g.toByteArray()))));
        System.out.println("\nk: " + k);

        //calculate v
        BigInteger v = Fast_modular_exp(x, g, p);

        //calculate g_b
        BigInteger pub_key_g_b = B.subtract(k.multiply(v)).mod(p);
        System.out.println("\npub_key_g_b: " + pub_key_g_b);

        //calculate u
        byte[] tmp = Hash(combine_array(check_sig(pub_key_g_a.toByteArray()), check_sig(pub_key_g_b.toByteArray())));
        BigInteger u = new BigInteger(1, tmp); // <-- force positive
        System.out.println("\nu: " + u);

        //shared_key
        BigInteger shared_key = Fast_modular_exp(a.add(u.multiply(x)), pub_key_g_b, p);
    
        System.out.println("\nshared key: " + shared_key);

        //calculate M1
        BigInteger tmp_p_xor_g = new BigInteger(Hash(check_sig(p.toByteArray()))).xor(new BigInteger(Hash(g.toByteArray())));
        byte[] netID = Hash(username.getBytes(StandardCharsets.UTF_8));
        byte[] m1 = combine_array(check_sig(tmp_p_xor_g.toByteArray()), netID);
        m1 = combine_array(m1, salt_array);
        m1 = combine_array(m1, pub_key_g_a.toByteArray());
        m1 = combine_array(m1, pub_key_g_b.toByteArray());
        m1 = combine_array(m1, shared_key.toByteArray());
        
        m1 = Hash(m1);
        System.out.println("\nm1: " + new BigInteger(1, m1).toString(16));
        
        byte[] m2 = Hash(combine_array(combine_array(pub_key_g_a.toByteArray(), m1), shared_key.toByteArray()));
        System.out.println("\nm2: " + new BigInteger(1,m2).toString(16));
    }
        



    public static BigInteger Fast_modular_exp(BigInteger exp, BigInteger g, BigInteger p) {
        BigInteger result = one;

        while (exp.compareTo(zero) > 0) { // while exp( or d) > 0
            if (exp.mod(two).equals(one)) { // if bit is set to 1
                result = result.multiply(g).mod(p);
            }

            g = g.multiply(g).mod(p);
            exp = exp.divide(two);
        }

        return result;
    }

    public static byte[] Hash(byte[] input) throws NoSuchAlgorithmException {
        //turn plaintext and hex into bytearray 

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



