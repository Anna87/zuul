package com.zuul.java.config;

import com.zuul.java.filter.JwtTokenAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletResponse;


@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    JwtConfig jwtConfig;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .exceptionHandling()
                .authenticationEntryPoint((request, response, e) -> {
                    String json = String.format("{\"message\": \"%s\"}", e.getMessage());
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.setCharacterEncoding("UTF-8");
                    response.getWriter().write(json);
                    response.addHeader("access-control-allow-origin","*");
                    response.setHeader("access-control-allow-origin","*");
                })
                .and()
                .addFilterAfter(new JwtTokenAuthenticationFilter(jwtConfig), UsernamePasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers(HttpMethod.POST, jwtConfig.getUri()).permitAll()
//                .antMatchers(HttpMethod.GET, "/library/book/addBook").hasRole("ADMIN")
//                .antMatchers(HttpMethod.GET, "/library/book/deleteBook").hasRole("ADMIN")
//                .antMatchers(HttpMethod.GET, "/library/book/editBook").hasRole("ADMIN")
//                .antMatchers(HttpMethod.GET, "/library/book/books").permitAll()
//                .antMatchers(HttpMethod.GET, "/library/holder/**").hasRole("ADMIN") // if on controller set pom return always 401
//                .antMatchers(HttpMethod.GET, "/library/borrow/**").hasRole("ADMIN")
                //.antMatchers("/gallery" + "/admin/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .anyRequest().authenticated();
    }

    @Bean
    public JwtConfig jwtConfig() {
        return new JwtConfig();
    }

}
