package com.example.springjwt.controller;


import com.example.springjwt.dto.JoinDto;
import com.example.springjwt.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

@ResponseBody
@Controller
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String JoinProcess(@RequestBody JoinDto joinDto){
        System.out.println(joinDto);
        joinService.joinProcess(joinDto);
        return "ok";
    }
}
