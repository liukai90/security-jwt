package com.lk.security.dto;

import lombok.Data;

/**
 * @author : liukai@acoinfo.com
 * @date : 2020-07-15 16:25
 * @description:
 */
@Data
public class Response {

    private Integer code;

    private String message;

    private Object data;

    public static Response SUCCESS(String message){
        Response response = new Response();
        response.setCode(20000);
        response.setMessage(message);
        return response;
    }
    public static Response FAIL(String message){
        Response response = new Response();
        response.setCode(10000);
        response.setMessage(message);
        return response;
    }


}
