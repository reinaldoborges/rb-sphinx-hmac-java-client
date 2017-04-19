package com.sphinx.rb.hmacapi.algorithm;

import com.sphinx.rb.hmacapi.exception.HMACHashException;
import com.sphinx.rb.hmacapi.exception.HMACKeyException;
import com.sphinx.rb.hmacapi.hmac.HMAC;

/**
 *
 * @author Luan Lino Matias dos Santos
 *
 */
public abstract class HMACAlgorithm {

    /**
     * Implementa o algoritmo de cálculo do HMAC.
     *
     * @param hmac
     * @param data
     * @return String
     *
     * @throws HMACKeyException
     * @throws com.sphinx.rb.hmacapi.exception.HMACHashException
     */
    public abstract String getHmac(HMAC hmac, String data) throws HMACKeyException , HMACHashException;

    /**
     *
     * @return string
     */
    public String __toString() {
        return getClass().getSimpleName();
    }
}
