package com.zosh.config;

import java.io.IOException;
import java.util.List;

import javax.crypto.SecretKey;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtValidator extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Lấy chuỗi JWT từ tiêu đề HTTP.
        String jwt = request.getHeader(JwtConstant.JWT_HEADER);

        if (jwt != null) {
            // Loại bỏ tiền tố "Bearer " để lấy chuỗi JWT.
            jwt = jwt.substring(7);
            try {
                // Tạo một khóa bí mật từ chuỗi được định nghĩa trong JwtConstant.
                SecretKey key = Keys.hmacShaKeyFor(JwtConstant.SECRET_KEY.getBytes());

                // Giải mã chuỗi JWT và lấy thông tin từ các phần tử trong chuỗi.
                Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwt).getBody();

                // Lấy email từ claims.
                String email = String.valueOf(claims.get("email"));

                // Lấy danh sách quyền (authorities) từ claims.
                String authorities = String.valueOf(claims.get("authorities"));

                // Chuyển đổi chuỗi quyền thành danh sách các đối tượng GrantedAuthority.
                List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList(authorities);

                // Xây dựng đối tượng Authentication từ thông tin xác thực.
                Authentication authentication = new UsernamePasswordAuthenticationToken(email, null, auths);

                // Đặt đối tượng Authentication vào SecurityContextHolder để xác thực người dùng.
                SecurityContextHolder.getContext().setAuthentication(authentication);

            } catch (Exception e) {
                // Nếu có lỗi trong quá trình giải mã JWT, ném một ngoại lệ BadCredentialsException.
                throw new BadCredentialsException("Invalid token... from jwt validator");
            }
        }
        // Chuyển giao xử lý cho các filter tiếp theo trong chuỗi filter.
        filterChain.doFilter(request, response);
    }
}
