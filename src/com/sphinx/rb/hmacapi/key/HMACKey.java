package com.sphinx.rb.hmacapi.key;

import com.sphinx.rb.hmacapi.algorithm.HMACAlgorithm;
import com.sphinx.rb.hmacapi.exception.HMACHashException;
import com.sphinx.rb.hmacapi.hmac.HMACSession;
import com.sphinx.rb.hmacapi.hmac.HMAC;
import com.sphinx.rb.hmacapi.exception.HMACKeyException;

/**
 *
 * @author Luan Lino Matias dos Santos
 *
 */
public abstract class HMACKey {

    /**
     *
     * @var string
     */
    protected String keyId;

    /**
     *
     * @return string
     */
    public String getId() {
        return this.keyId;
    }

    /**
     *
     * @param keyId
     * @return HMACKey
     */
    protected HMACKey setId(String keyId) {
        this.keyId = keyId;
        return this;
    }

    /**
     * Retorna a string da chave a ser utilizada
     *
     * @param keyId
     * @return string
     */
    public abstract String getKeyValue(String keyId);

    /**
     * Retorna chave composta a ser usada no HMAC
     *
     * @param hmac
     * @return string
     * @throws com.sphinx.rb.hmacapi.exception.HMACKeyException
     * @throws com.sphinx.rb.hmacapi.exception.HMACHashException
     */
    public String getCompositeKey(HMAC hmac) throws HMACKeyException, HMACHashException {
        String hmacKey = "";

        if (hmac == null) {
            throw new HMACKeyException("HMAC não iniciado");//, 5 );
        }
        HMACAlgorithm algo = hmac.getAlgorithm();
        this.setId(hmac.getKeyId());

        if (hmac instanceof HMACSession) {
            /**
             * Composição da chave para HMAC com Sessão
             */

            if (hmac.getDataType() == 0) {
                throw new HMACKeyException("Chave precisa do DATATYPE para sua composição");//, 3 );
            }
            /**
             * Ajustar composição de acordo com o tipo da mensagem
             */
            switch (hmac.getDataType()) {
                case HMACSession.SESSION_REQUEST:
                    /**
                     * Requisição de início de sessão: NONCE + KEY
                     */
                    hmacKey = hmac.getNonceValue() + this.getKeyValue(this.keyId);
                    break;
                case HMACSession.SESSION_RESPONSE:
                    /**
                     * Resposta à requisição de início de sessão: NONCE + KEY +
                     * NONCE2
                     */

                    hmacKey = hmac.getNonceValue() + this.getKeyValue(this.keyId) + hmac.getNonce2Value();
                    break;
                case HMACSession.SESSION_MESSAGE:
                    /**
                     * Mensagens dentro da sessão: NONCE + KEY + CONTADOR +
                     * NONCE2
                     */
                    if (hmac.getContador() == 0) {
                        throw new HMACKeyException("Sessão HMAC não iniciada");//, 5 );
                    }
                    hmacKey = hmac.getNonceValue() + this.getKeyValue(this.keyId) + hmac.getContador() + hmac.getNonce2Value();
                    break;
                default:
                    throw new HMACKeyException("Tipo de mensagem HMAC desconhecida");//, 6 );
            }
        } else if (hmac instanceof HMAC) {
            /**
             * Composição da chave para HMAC simples (sem sessão)
             */
            hmacKey = hmac.getNonceValue() + this.getKeyValue(this.keyId);
        } else {
            throw new HMACKeyException("Tipo de HMAC desconhecido");//, 1 );
        }

        return hmacKey;
    }

    /**
     *
     * @return string
     */
    public String __toString() {
        return getClass().getSimpleName();
    }

    public String getKeyString(String keyId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
