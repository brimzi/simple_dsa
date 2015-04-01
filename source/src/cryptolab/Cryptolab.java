/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptolab;
import java.io.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Scanner;
/**
 *
 * @author brimzy
 */
public class Cryptolab {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception{
       
       // while(true){
        //String fileName=getFileName();
        /*if(fileName.equals("quit")){
            System.out.println("Exiting.....");
            System.exit(0);
        }*/
        
        Scanner in =new Scanner(System.in);
        
        //read pqg from file
        ParameterTuple tuple=readTuple(in);
        
        //check if group is valid
        if(!Utility.isTupleValid(tuple)){
            System.out.println("invalid_group\n\n");
            System.exit(1);
        }else System.out.println("valid_group");
        
        //read the type of operation to perform
        String cmd=in.nextLine().trim();
        
        //execute the specified command
        executeCommand(cmd, in, tuple);
       // }
        
        
        
    }

    private static void generateKeys(int n,ParameterTuple tuple) {
        for(int i=0;i<n;i++){
            PubPrivPair pair=Utility.generatePubPrivpair(tuple);
            System.out.printf("X = %d \nY = %d\n",pair.x,pair.y);
        }
    }

    private static void signMessages(ParameterTuple tuple, PubPrivPair pubPrivPair,ArrayList<String> digests) {
        DSAUser user=new DSAUser(pubPrivPair, tuple);
        for(String s:digests){
            BigInteger d=new BigInteger(s,16);
            
            Signature sig=user.sign(d);
            
            System.out.printf("r = %d\n",sig.getR());
            System.out.printf("s = %d\n\n",sig.getS());
        }
    }

    static ParameterTuple readTuple(Scanner in) throws IOException {
        String p=in.nextLine().split("=")[1];
        String q=in.nextLine().split("=")[1];
        String g=in.nextLine().split("=")[1];
        ParameterTuple tuple=new ParameterTuple(new BigInteger(p),new BigInteger(q),new BigInteger(g));
        return tuple;
    }

    static void executeCommand(String cmd, Scanner reader, ParameterTuple tuple) throws IOException, NumberFormatException {
        switch(cmd){
            case "genkey":
                String nS=reader.nextLine().split("=")[1];
                int n=Integer.parseInt(nS);
                generateKeys(n,tuple);
                break;
            case "sign":
                BigInteger x=new BigInteger(reader.nextLine().split("=")[1]);
                BigInteger y=new BigInteger (reader.nextLine().split("=")[1]);
                ArrayList<String> digests=new ArrayList<>();
                String d;
                while(reader.hasNextLine()&&(d=reader.nextLine())!=null && !d.trim().equals("")){
                    d=d.split("=")[1];
                    digests.add(d);
                }
                
                signMessages(tuple,new PubPrivPair(x, y),digests);
                
                break;
                
            case "verify":
                BigInteger y2=new BigInteger (reader.nextLine().split("=")[1]);
                while(reader.hasNextLine()&&(d=reader.nextLine())!=null && !d.trim().equals("") ){
                    d=d.split("=")[1];
                    BigInteger r=new BigInteger(reader.nextLine().split("=")[1]);
                    BigInteger s=new BigInteger (reader.nextLine().split("=")[1]);
                    Signature sig=new Signature(s, r);
                    DSAUser user=new DSAUser(new PubPrivPair(BigInteger.ZERO, y2), tuple);
                    
                    if(user.verify(new BigInteger(d,16), sig))
                        System.out.println("signature_valid");
                    else 
                        System.out.println("signature_invalid");
                }
                break;
        }
    }

    private static String getFileName() {
        Scanner s=new Scanner(System.in);
        System.out.println("\nPlease enter the file name to process and press enter, or type 'quit' to exit");
        String fileName=s.nextLine();
        
        return fileName;
    }
}
