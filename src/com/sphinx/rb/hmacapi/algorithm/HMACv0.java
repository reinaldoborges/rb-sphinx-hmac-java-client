package com.sphinx.rb.hmacapi.algorithm;

import com.sphinx.rb.hmacapi.exception.HMACHashException;
import com.sphinx.rb.hmacapi.exception.HMACKeyException;
import com.sphinx.rb.hmacapi.hmac.HMAC;

/**
 *
 * @author Luan Lino Matias dos Santos
 *        
 */
public class HMACv0 extends HMACAlgorithm {
	/**
	 * Implementa o algoritmo de cálculo do HMAC.
	 *
	 * @param hmac        	
	 * @param data        	
	 * @return string
	 *
	 * @throws HMACKeyException
         * @throws com.sphinx.rb.hmacapi.exception.HMACHashException
	 */
        @Override
	public String getHmac(HMAC hmac, String data) throws HMACKeyException , HMACHashException{
                return hmac.getHash ( hmac.getHash ( hmac.getCompositeKey () ) + data );
	}
      
}
