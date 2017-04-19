package com.sphinx.rb.hmacapi.nonce;

/**
 * !!! ATENÇÃO !!!
 * Não gera o nonce, apenas mostra os dados em TEXTO CLARO.
 * Propósito didático para demonstrar funcionamento do protocolo.
 *
 * NÃO USE EM AMBIENTE DE PRODUÇÃO!!!
 *
 * @author Luan Lino
 *        
 */
public class DummyNonce extends HMACNonce {
	public String generate() {
		this.nonce = "[NONCE]";
		return this.nonce;
	}
	public boolean validate(String nonce) {
		return true;
	}
        
//        public String __toString(){
//            return getClass().getSimpleName();
//        }
}
