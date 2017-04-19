package com.sphinx.rb.hmacapi.hash;

import com.sphinx.rb.hmacapi.exception.HMACHashException;

/**
 *
 * @author Luan Lino Matias dos Santos
 *
 */
public class Sha256 extends HMACHash {

    /**
     *
     * @return 
     * @throws com.sphinx.rb.hmacapi.exception.HMACHashException
     * @see com.​sphinx.rb.​hmacapi.​hash.HMACHash.getHash()
     */
    public String getHash(String data) throws HMACHashException {
        JAVAHash hash = null;

        hash = new JAVAHash("SHA-256");

        return hash.getHash(data);
    }

}
