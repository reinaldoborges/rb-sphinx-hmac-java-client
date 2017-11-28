/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sphinx.rb.hmachttpclient.util;


/**
 *
 * @author luan
 */
public class JSON {
    
    
    public void encode(){
        JSONObject obj=new JSONObject();
  obj.put("name","foo");
  obj.put("num",new Integer(100));
  obj.put("balance",new Double(1000.21));
  obj.put("is_vip",new Boolean(true));
//  obj.put("nickname",null);
  System.out.print(obj);
    }
    
    
}
