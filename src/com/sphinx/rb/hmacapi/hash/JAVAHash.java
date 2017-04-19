package com.sphinx.rb.hmacapi.hash;

import com.sphinx.rb.hmacapi.exception.HMACHashException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Biblioteca Hash do JAVA
 *
 * @author Luan Lino Matias dos Santos
 *
 */
public class JAVAHash extends HMACHash {

    protected MessageDigest md;

    /**
     * Algortimo a ser utilizado
     *
     * @var hashAlgo - String
     */
    protected String hashAlgo;

    public JAVAHash(String hashAlgo) throws HMACHashException {

        try {

            /**
             * Verificar se algoritmo está disponível
             */
            md = MessageDigest.getInstance(hashAlgo);

        } catch (NoSuchAlgorithmException ex) {
            throw new HMACHashException("Algoritmo de hash " + hashAlgo + " não está disponível.\n" + ex);
        }

        this.hashAlgo = hashAlgo;

    }

    /**
     *
     * @param data - String com os dados que deseja obter o hash.
     *
     * @throws com.sphinx.rb.hmacapi.exception.HMACHashException
     * @return String
     *
     * @see com.​sphinx.rb.​hmacapi.​hash.HMACHash.getHash()
     */
    @Override
    public String getHash(String data) throws HMACHashException {
        byte[] digest = null;
        String hash = null;
        try {
            md.update(data.getBytes("UTF-8"));
            digest = md.digest();

            StringBuffer hexaString = new StringBuffer();

            for (int i = 0; i < digest.length; i++) {
                String hex = Integer.toHexString(0xff & digest[i]);
                if (hex.length() == 1) {
                    hexaString.append('0');
                }
                hexaString.append(hex);
            }

            hash = hexaString.toString();

        } catch (Exception e) {
            throw new HMACHashException(e.getMessage());
        }

        return hash;
    }

    /**
     *
     * @return String
     * @see com.​sphinx.rb.​hmacapi.​hash.HMACHash.__toString()
     */
    public String __toString() {

        return this.hashAlgo;

    }
}
