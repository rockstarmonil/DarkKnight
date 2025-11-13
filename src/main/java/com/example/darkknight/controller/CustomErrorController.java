package com.example.darkknight.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class CustomErrorController implements ErrorController {

    @RequestMapping("/error")
    public String handleError(HttpServletRequest request, Model model) {
        // Get error status code
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        Object errorMessage = request.getAttribute(RequestDispatcher.ERROR_MESSAGE);
        Object exception = request.getAttribute(RequestDispatcher.ERROR_EXCEPTION);

        System.out.println("❌ Error page accessed");
        System.out.println("   - Status: " + status);
        System.out.println("   - Message: " + errorMessage);
        System.out.println("   - Exception: " + (exception != null ? exception.getClass().getName() : "None"));

        // Add error details to model
        if (status != null) {
            int statusCode = Integer.parseInt(status.toString());
            model.addAttribute("status", statusCode);

            switch (statusCode) {
                case 403:
                    model.addAttribute("error", "Access Forbidden");
                    model.addAttribute("message", "You don't have permission to access this resource. Please login or contact your administrator.");
                    break;
                case 404:
                    model.addAttribute("error", "Page Not Found");
                    model.addAttribute("message", "The page you're looking for doesn't exist.");
                    break;
                case 500:
                    model.addAttribute("error", "Internal Server Error");
                    model.addAttribute("message", "Something went wrong on our end. Please try again later.");
                    break;
                default:
                    model.addAttribute("error", "Error");
                    model.addAttribute("message", "An error occurred while processing your request.");
            }
        } else {
            model.addAttribute("status", 500);
            model.addAttribute("error", "Error");
            model.addAttribute("message", "An unexpected error occurred.");
        }

        if (errorMessage != null) {
            model.addAttribute("errorMessage", errorMessage.toString());
        }

        return "error";
    }
}