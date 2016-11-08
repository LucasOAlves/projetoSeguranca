//package atnf.atoms.mon.util;

package sec;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RSA {
    private BigInteger n, d, e;
    private int bitlen = 1024;
    
    /** Create an instance that can encrypt using someone elses public key. */
    public RSA(BigInteger newn, BigInteger newe) {
        n = newn;
        e = newe;
    }
    
    /** Create an instance that can both encrypt and decrypt. */
    public RSA(int bits) {
        bitlen = bits;
        SecureRandom r = new SecureRandom();
        BigInteger p = new BigInteger(bitlen / 2, 100, r);
        BigInteger q = new BigInteger(bitlen / 2, 100, r);
        n = p.multiply(q);
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q
                .subtract(BigInteger.ONE));
        e = new BigInteger("3");
        while (m.gcd(e).intValue() > 1) {
            e = e.add(new BigInteger("2"));
        }
        d = e.modInverse(m);
    }
    
    public synchronized String encryptWithPublic(String message){
        String[] fragments = fragmentMessage(message);
        String encryptedMessage = "";
        for(int i=0;i<fragments.length;i++){
            encryptedMessage += (new BigInteger(fragments[i].getBytes())).modPow(e, n).toString(16)+" ";
        }
        return encryptedMessage;
    }
    
    public synchronized String encryptWithPrivate(String message){
        String[] fragments = fragmentMessage(message);
        String encryptedMessage = "";
        for(int i=0;i<fragments.length;i++){
            encryptedMessage += (new BigInteger(fragments[i].getBytes())).modPow(d, n).toString(16)+" ";
        }
        return encryptedMessage;
    }
    
    public synchronized String decryptWithPublic(String message){
        String[] fragments = message.split(" ");
        String decrypted = "";
        for(String s : fragments){
            decrypted += new String((new BigInteger(s,16)).modPow(e, n).toByteArray());
        }
        return decrypted;
    }
    
    public synchronized String decryptWithPrivate(String message){
        String[] fragments = message.split(" ");
        String decrypted = "";
        for(String s : fragments){
            decrypted += new String((new BigInteger(s,16)).modPow(d, n).toByteArray());
        }
        return decrypted;
    }
    
    /** Generate a new public and private key set. */
    public synchronized void generateKeys() {
        SecureRandom r = new SecureRandom();
        BigInteger p = new BigInteger(bitlen / 2, 100, r);
        BigInteger q = new BigInteger(bitlen / 2, 100, r);
        n = p.multiply(q);
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q
                .subtract(BigInteger.ONE));
        e = new BigInteger("3");
        while (m.gcd(e).intValue() > 1) {
            e = e.add(new BigInteger("2"));
        }
        d = e.modInverse(m);
    }
    
    /** Return the modulus. */
    public synchronized BigInteger getN() {
        return n;
    }
    
    public synchronized void setN(BigInteger n) {
        this.n = n;
    }
    
    /** Return the public key. */
    public synchronized BigInteger getE() {
        return e;
    }
    
    public synchronized void setE(BigInteger e){
        this.e = e;
    }
    
    public synchronized void setD(BigInteger d){
        this.d = d;
    }
    
    public static void main(String[] args) {
        RSA rsaSender = new RSA(1024);
        RSA rsaReceiver = new RSA(1024);
        String sent = rsaSender.sendMessage("MURILO", rsaReceiver.getN(), rsaReceiver.getE());
        System.out.println("Sent: "+sent);
        String received = rsaReceiver.receiveMessage(sent, rsaSender.getN(), rsaSender.getE());
        System.out.println("Received: "+received);
    }
    
    public synchronized String sendMessage(String plainTextMessage, BigInteger n, BigInteger e){
        try{
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String hashedSignature = "";
            byte[] hash = digest.digest(plainTextMessage.getBytes(StandardCharsets.UTF_8));
            for(int i=0;i<hash.length;i++){
                hashedSignature += String.format("%02X", hash[i] & 0xFF);
            }
            RSA publicKey = new RSA(n, e);
            String fullCipherMsg = publicKey.encryptWithPublic(encryptWithPrivate(hashedSignature)+" "+plainTextMessage);
            return fullCipherMsg;
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return null;
    }
    
    public synchronized String receiveMessage(String message, BigInteger n, BigInteger e){
        String decrypted = decryptWithPrivate(message);
        String signature = decrypted.substring(0,decrypted.indexOf(" "));
        String msg = decrypted.substring(decrypted.indexOf(" ")+2);
        RSA publicKey = new RSA(n,e);
        String decryptedSignature = publicKey.decryptWithPublic(signature);
        String hashedMessage = hashText(msg);
        if(hashedMessage.equals(decryptedSignature)){
            return msg;
        }else{
            return "MESSAGE NOT SECURE!!!";
        }
    }
    
    public String[] fragmentMessage(String message){
        int fragmentation = 128;
        int fragmentsLength = message.length()/fragmentation + 1*((message.length()%fragmentation>0)?(1):(0));
        String[] fragments = new String[fragmentsLength];
        for(int i=0,j=0,k=fragmentation;i<fragmentsLength;i++,j=k,k+=fragmentation){
            if(k<message.length())
                fragments[i] = message.substring(j, k);
            else
                fragments[i] = message.substring(j);
        }
        return fragments;
    }
    
    public String hashText(String text){
        try {
            MessageDigest digestor = MessageDigest.getInstance("SHA-256");
            byte[] msgHash = digestor.digest(text.getBytes());
            String hashedText = "";
            for(int i=0;i<msgHash.length;i++){
                hashedText += String.format("%02X", msgHash[i] & 0xFF);
            }
            return hashedText;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
}
