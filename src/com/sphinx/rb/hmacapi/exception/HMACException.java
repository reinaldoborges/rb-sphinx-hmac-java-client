package com.sphinx.rb.hmacapi.exception;

/**
 *
 * @author Luan Lino Matias dos Santos
 */
public class HMACException extends Exception{
    
     public HMACException(){
         super();
     }
    
    public HMACException(String message){
        super(message);
    }
    
}
