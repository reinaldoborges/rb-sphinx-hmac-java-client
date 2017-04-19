
package com.sphinx.rb.hmacapi.hash;

/**
 * !!! ATENÇÃO !!!
 * Não calcula o hash, apenas mostra os dados em TEXTO CLARO.
 * Propósito didático para demonstrar funcionamento do protocolo.
 * 
 * NÃO USE COM CHAVES REAIS OU AMBIENTE DE PRODUÇÃO!!!
 * 
 * @author Luan Lino Matias dos Santos
 *        
 */
public class DummyHash extends HMACHash {
	/**
	 * 
         * @param data
	 * @see com.sphinx.rb.hmacapi.hash.HMACHash
	 */
	public String getHash(String data) {
		return "H(" + data.replace(":","|") + ")";
	}
        
        public String __toString(){
            return getClass().getSimpleName();
        }
}
