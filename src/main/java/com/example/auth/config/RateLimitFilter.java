package com.example.auth.config;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private final AuthProperties authProperties;
    private final Map<String, Bucket> loginBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> resetBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> socialBuckets = new ConcurrentHashMap<>();

    public RateLimitFilter(AuthProperties authProperties) {
        this.authProperties = authProperties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        if (!HttpMethod.POST.matches(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        String key = request.getRemoteAddr();
        boolean allowed = true;
        if (path.equals("/api/v1/login")) {
            allowed = loginBuckets.computeIfAbsent(key, this::newLoginBucket).tryConsume(1);
        } else if (path.equals("/api/v1/password-reset")) {
            allowed = resetBuckets.computeIfAbsent(key, this::newResetBucket).tryConsume(1);
        } else if (path.equals("/api/v1/login/social")) {
            allowed = socialBuckets.computeIfAbsent(key, this::newSocialBucket).tryConsume(1);
        }

        if (!allowed) {
            response.setStatus(429);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":{\"code\":\"RATE_LIMITED\",\"message\":\"Too many requests\",\"details\":{}}}");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private Bucket newLoginBucket(String ignored) {
        return Bucket.builder()
                .addLimit(Bandwidth.classic(authProperties.getRateLimit().getLoginPerMinute(), Refill.greedy(authProperties.getRateLimit().getLoginPerMinute(), Duration.ofMinutes(1))))
                .build();
    }

    private Bucket newResetBucket(String ignored) {
        return Bucket.builder()
                .addLimit(Bandwidth.classic(authProperties.getRateLimit().getPasswordResetPerMinute(), Refill.greedy(authProperties.getRateLimit().getPasswordResetPerMinute(), Duration.ofMinutes(1))))
                .build();
    }

    private Bucket newSocialBucket(String ignored) {
        return Bucket.builder()
                .addLimit(Bandwidth.classic(authProperties.getRateLimit().getSocialLoginPerMinute(), Refill.greedy(authProperties.getRateLimit().getSocialLoginPerMinute(), Duration.ofMinutes(1))))
                .build();
    }
}
