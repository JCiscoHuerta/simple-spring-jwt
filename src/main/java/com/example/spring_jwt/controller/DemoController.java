package com.example.spring_jwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

    @GetMapping("/demo")
    public ResponseEntity<String> demo() {
        return ResponseEntity.ok("Welcome");
    }

    @GetMapping("/admin_only")
    public ResponseEntity<String> adminonly() {
        return ResponseEntity.ok("admin?");
    }

}
