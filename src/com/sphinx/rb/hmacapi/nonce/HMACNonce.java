package com.sphinx.rb.hmacapi.nonce;

import com.sphinx.rb.hmacapi.exception.HMACHashException;
import com.sphinx.rb.hmacapi.exception.HMACNonceException;

/**
 *
 * @author Luan Lino
 *        
 */
public abstract class HMACNonce {
	
	/**
	 *
	 * @var string
	 */
	protected String nonce = null;
	
	/**
	 * Gera novo nonce.
	 *
	 * @return string
	 */
	public abstract String generate() throws HMACHashException;
	
	/**
	 * Verificar se nonce informado atende aos requisitos
	 *
	 * @param string $nonce        	
	 * @return bool
	 * @throws HMACNonceException
	 */
	public abstract boolean validate(String nonce)throws HMACNonceException;
	
	/**
	 * Retorna nonce.
	 * Gera um novo se ainda não existir.
	 *
	 * @return string
	 */
	public String getNonce() throws HMACHashException {
		if (this.nonce == null)
			this.generate ();
		return this.nonce;
	}
	
	/**
	 *
	 * @param string $nonce        	
	 * @return \RB\Sphinx\Hmac\Nonce\HMACNonce
	 */
	public HMACNonce setNonce(String nonce) {
		this.nonce = nonce;
		return this;
	}
	
	/**
	 *
	 * @return string
	 */
	public String __toString() {
        return getClass().getSimpleName();
	}
}
