package com.example.darkknight;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class DarkKnightApplication {

    public static void main(String[] args) {
        SpringApplication.run(DarkKnightApplication.class, args);
        System.out.println("🚀 DarkKnight Application is running on http://localhost:8080");
    }
}
