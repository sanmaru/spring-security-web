package com.sanmaru.web.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.Enumeration;

@Controller
public class RootController {

    final static Logger logger = LoggerFactory.getLogger(RootController.class);

    @GetMapping("/")
    public String index(Model model
            , @RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient
            , @AuthenticationPrincipal OAuth2User oAuth2User
            , HttpServletRequest request
            , HttpServletResponse response ){
        HttpSession session = (HttpSession)request.getSession();
        Enumeration enumSession = session.getAttributeNames();
        while(enumSession.hasMoreElements()){
            String key = (String) enumSession.nextElement();
            System.out.println(key + " : " + session.getAttribute(key));
        }
        model.addAttribute("userName", "userName");
        model.addAttribute("clientName", "clientName");
        model.addAttribute("userAttributes", oAuth2User.getAttributes());

        System.out.println("AccessToken : " + authorizedClient.getAccessToken().getTokenValue());
        System.out.println("RefreshToken : " + authorizedClient.getRefreshToken().getTokenValue());
        return "index";
    }
}
