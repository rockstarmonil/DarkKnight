package com.example.darkknight.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Root controller to handle main domain access
 * Redirects root path to login page
 */
@Controller
public class RootController {

    /**
     * Redirect root path to login
     * When someone visits https://pingmyserver.cfd they go to /login
     */
    @GetMapping("/")
    public String redirectToLogin() {
        System.out.println("🏠 Root path accessed - redirecting to /login");
        return "redirect:/login";
    }

    /**
     * Handle /home path (optional)
     */
    @GetMapping("/home")
    public String home() {
        System.out.println("🏠 Home path accessed - redirecting to /login");
        return "redirect:/login";
    }
}