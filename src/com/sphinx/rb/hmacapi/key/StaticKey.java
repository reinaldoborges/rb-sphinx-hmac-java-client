package com.sphinx.rb.hmacapi.key;

import com.sphinx.rb.hmacapi.exception.HMACKeyException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Luan Lino
 *        
 */
public class StaticKey extends HMACKey {
	
	/**
	 *
	 * @var string
	 */
	protected String key = null;
	
	/**
	 *
	 * @param string $key
	 *        	Chave estática a ser utilizada
	 */
	public StaticKey(String key) {
		this.key = key;
	}
	
	/**
	 *
	 * @see HMACKey.getKeyString()
	 */
        @Override
	public String getKeyValue(String keyId){
		this.setId ( keyId );
		
		if (this.key == null){
                    try {
                        throw new HMACKeyException ( "Chave não definida");//, 101 );
                    } catch (HMACKeyException ex) {
                        return null;
                    }
                }
		return this.key;
	}
	
}