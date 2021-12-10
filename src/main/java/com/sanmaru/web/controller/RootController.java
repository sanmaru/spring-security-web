package com.sanmaru.web.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
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
            logger.info("======= " + key + " : " + session.getAttribute(key));
        }
        CsrfToken token = new HttpSessionCsrfTokenRepository().loadToken(request);
        if (token != null) {
            logger.info("======= " + "CsrfToken : " + token.getToken());
            model.addAttribute("_csrf", token.getToken());
        }

        model.addAttribute("userName", "userName");
        model.addAttribute("clientName", "clientName");
        model.addAttribute("userAttributes", oAuth2User.getAttributes());


        logger.info("======= " + "AccessToken : " + authorizedClient.getAccessToken().getTokenValue());
        logger.info("======= " + "RefreshToken : " + authorizedClient.getRefreshToken().getTokenValue());
        return "index";
    }

    @GetMapping("/sample")
    public String sample(Model model
            , @RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient
            , @AuthenticationPrincipal OAuth2User oAuth2User
            , HttpServletRequest request
            , HttpServletResponse response ){
        HttpSession session = (HttpSession)request.getSession();
        Enumeration enumSession = session.getAttributeNames();
        while(enumSession.hasMoreElements()){
            String key = (String) enumSession.nextElement();
            logger.info("======= " + key + " : " + session.getAttribute(key));
        }

        model.addAttribute("userName", "userName");
        model.addAttribute("clientName", "clientName");
        model.addAttribute("userAttributes", oAuth2User.getAttributes());

        logger.info("======= " + "AccessToken : " + authorizedClient.getAccessToken().getTokenValue());
        logger.info("======= " + "RefreshToken : " + authorizedClient.getRefreshToken().getTokenValue());
        return "sample";
    }
/*
    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response){
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated()) {
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }
        return "redirect:/";
    }

 */
}
