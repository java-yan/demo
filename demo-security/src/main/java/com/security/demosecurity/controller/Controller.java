package com.security.demosecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @author yan
 * @Date:2019/9/3
 */
@RestController
public class Controller {

    @GetMapping("/a")
    public String a(){
        return "haha";
    }
    @GetMapping("/login")
    public Map b(){
        HashMap<String, Object> map = new HashMap<>();
        map.put("status","302");
        map.put("msg","请先登录");
        return map;
    }
}
