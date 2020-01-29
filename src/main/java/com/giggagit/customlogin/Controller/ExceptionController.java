package com.giggagit.customlogin.Controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * ExceptionController
 */
@Controller
public class ExceptionController {

    @RequestMapping("/access-denied")
    public String accessDenied() {
        return "error/403";
    }
    
}