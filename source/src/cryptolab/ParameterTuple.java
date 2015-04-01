/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptolab;
import java.math.BigInteger;
/**
 *
 * @author brimzy
 */
public class ParameterTuple {
    private BigInteger p,q,g;
    
    public ParameterTuple(BigInteger p,BigInteger q,BigInteger g){
        this.p=p;
        this.q=q;
        this.g=g;     
    }
    
    public BigInteger getP(){
        return p;
    }
    
    public BigInteger getQ(){
        return q;
    }
    
    public BigInteger getG(){
        return g;
    }
}

 class Signature{
    private BigInteger s,r;
    public Signature(BigInteger s,BigInteger r){
        this.s=s;
        this.r=r;
    }
    
    public BigInteger getS(){
        return s;
    }
    
    public BigInteger getR(){
        return r;
    }
}

class PubPrivPair{
    BigInteger x,y;
    PubPrivPair(BigInteger privKey,BigInteger pubKey){
        this.x=privKey;
        this.y=pubKey;
    }
    
    public BigInteger getPrivKey(){
        return x;
    }
    
    public BigInteger getPubkey(){
        return y;
    }
    
}


