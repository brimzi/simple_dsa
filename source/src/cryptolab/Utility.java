/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptolab;
import java.math.BigInteger;
import java.security.SecureRandom;
/**
 *
 * @author brimzy
 */
public class Utility {
    
    public static boolean isTupleValid(ParameterTuple pt){
        BigInteger p=pt.getP();
        BigInteger q=pt.getQ();
        BigInteger g=pt.getG();
        int certainty =10;
        
        if(p.compareTo(g)<1)
            return false;
        //both p and q are primes;
        if(!p.isProbablePrime(certainty)||!q.isProbablePrime(certainty))
                return false;
        
        //p is a 1024 bit number and q a 160 bit number
        if(p.bitLength()!=1024 || q.bitLength()!=160)
            return false;
        
        //q is a divisor of p-1
        BigInteger[] res=p.subtract(new BigInteger("1")).divideAndRemainder(q);
        if(!res[1].equals(new BigInteger("0")))
            return false;
        
        //g has order q i.e. g^q mod p = 1 and g > 1.
        if(g.compareTo(BigInteger.ONE)<1||!g.modPow(q, p).equals(BigInteger.ONE))
            return false;
        
        return true;
    }
    
    public static PubPrivPair generatePubPrivpair(ParameterTuple pt){
        BigInteger p=pt.getP();
        BigInteger q=pt.getQ();
        BigInteger g=pt.getG();
        SecureRandom rnd=new SecureRandom();
        byte[] bytes=new byte[28];//28 bytes =160 + 64 bits,according to spec
        rnd.nextBytes(bytes);
        BigInteger c=new BigInteger(bytes);
        c=c.abs();//make sure c > 0
        
        BigInteger x=c.mod(q.subtract(BigInteger.ONE)).add(BigInteger.ONE);//generate x
        BigInteger y=g.modPow(x, p);//generate y
        return new PubPrivPair(x,y);
    }
}
