package com.sanmaru;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class WebApplication {

    final static Logger logger = LoggerFactory.getLogger(WebApplication.class);

    public static void main(String[] args){
        SpringApplication.run(WebApplication.class, args);
    }
}
