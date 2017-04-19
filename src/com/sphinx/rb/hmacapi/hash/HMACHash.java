package com.sphinx.rb.hmacapi.hash;

import com.sphinx.rb.hmacapi.exception.HMACHashException;

/**
 *
 * @author Luan Lino Matias dos Santos
 *
 */
public abstract class HMACHash {

    /**
     * Calcula o HASH a ser utilizado pelo HMAC.
     *
     * @param data - String com os dados de entrada da função de hash
     * @return string
     * @throws HMACHashException
     */
    public abstract String getHash(String data)throws HMACHashException;

    /**
     *
     * @return string
     */
    public String __toString() {
        return getClass().getSimpleName();
    }
}
