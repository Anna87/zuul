package com.zuul.java.filter;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import com.zuul.java.config.JwtConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

import static org.springframework.cloud.netflix.zuul.filters.support.FilterConstants.SIMPLE_HOST_ROUTING_FILTER_ORDER;

/**
 * Created by alexpench on 18/05/2019.
 */
@Component
public class UserHeadersFilter extends ZuulFilter {
    @Autowired
    private JwtConfig jwtConfig;

    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return SIMPLE_HOST_ROUTING_FILTER_ORDER - 1;
    }

    @Override
    public boolean shouldFilter() {
       return !RequestContext.getCurrentContext().get("requestURI").equals("/auth");
    }

    @Override
    public Object run() throws ZuulException {
        final RequestContext currentContext = RequestContext.getCurrentContext();

        final String token = currentContext.getRequest().getHeader("authorization").substring(jwtConfig.getPrefix().length());

        Jws<Claims> claimsJws = Jwts.parser().setSigningKey(jwtConfig.getSecret().getBytes()).parseClaimsJws(token);
        List<String> roles = claimsJws.getBody().get("authorities", List.class);
        String username = claimsJws.getBody().getSubject();

        currentContext.addZuulRequestHeader("sub", username);
        currentContext.addZuulRequestHeader("authorities", String.join(", ", roles));

        return null;
    }
}
