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
public class DSAUser {
    
    private ParameterTuple parameterTuple;
    private PubPrivPair pubPrivPair;
  
    public DSAUser(PubPrivPair pubPriv,ParameterTuple tuple){
        if(Utility.isTupleValid(tuple)){
            this.parameterTuple=tuple;
            this.pubPrivPair=pubPriv;
        }else throw new IllegalArgumentException(" the provided tuple is not valid");
        
    }
    
    
    public Signature sign(BigInteger digest){
        BigInteger p=parameterTuple.getP();
        BigInteger q=parameterTuple.getQ();
        BigInteger g=parameterTuple.getG();
        BigInteger x=pubPrivPair.x;
        
        while(true){
            //generate random K
        BigInteger k = generateK();
        
        //create the inverse of K
        BigInteger kInverse=k.modInverse(q);
        
        //calculate r =(g^k mod p) mod q
        BigInteger r= g.modPow(k,p).mod(q);
        //check r is not zero
        if(r.equals(BigInteger.ZERO))
            continue;
        //calculate z
        BigInteger z = digest;//fixed in this case
        
        //calculate s = ( k^−1 (z + xr)) mod q
        BigInteger s = kInverse.multiply(z.add(x.multiply(r))).mod(q);
        //check s is not zero
        if(s.equals(BigInteger.ZERO))
            continue;
        
        return new Signature(s,r);
        }
        
    }
    
    public boolean verify(BigInteger digest,Signature sig){
        BigInteger s=sig.getS();
        BigInteger r=sig.getR();
        BigInteger p=parameterTuple.getP();
        BigInteger q=parameterTuple.getQ();
        BigInteger g=parameterTuple.getG();
        BigInteger y =pubPrivPair.y;
        
        //check that s is withing range i.e 0 < s < q
        if(s.compareTo(BigInteger.ZERO)<=0 ||s.compareTo(parameterTuple.getQ())>=0)
            return false;
        //check that r is withing range i.e 0 < r < q
        if(r.compareTo(BigInteger.ZERO)<=0 ||r.compareTo(parameterTuple.getQ())>=0)
            return false;
        
        //calculate w = (s′)^–1 mod q.
        BigInteger w= s.modInverse(q);
        
        //z
        BigInteger z=digest;
        
        //calculate u1 = (zw) mod q
        BigInteger u1=z.multiply(w).mod(q);
        
        //calculate u2 = ((r′)w) mod q
        BigInteger u2=r.multiply(w).mod(q);
        
        //calculate v = (((g)^u1 (y)^u2) mod p) mod q
        BigInteger v = g.modPow(u1,p).multiply(y.modPow(u2,p)).mod(p).mod(q);
        
        return v.equals(r);
    }

    BigInteger generateK() {
        SecureRandom rnd=new SecureRandom();
        byte[] bytes=new byte[20];//20 bytes =160 bits
        rnd.nextBytes(bytes);//get random bytes
        BigInteger k=new BigInteger(bytes);
        while(k.compareTo(BigInteger.ZERO)<=0 ||k.compareTo(parameterTuple.getQ())>=0){//make sure k is within range
            rnd.nextBytes(bytes);
            k=new BigInteger(bytes);
        }
        return k;
    }
   
}
