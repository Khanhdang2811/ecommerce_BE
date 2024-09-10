package com.zosh.config;

import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtProvider {
    // Khởi tạo một khóa bí mật sử dụng thuật toán HS256.
	private SecretKey key = Keys.hmacShaKeyFor(JwtConstant.SECRET_KEY.getBytes());
    public String generateToken(Authentication auth) {
      // Tạo chuỗi JWT dựa trên thông tin xác thực (Authentication).
        String jwt = Jwts.builder()
                .setIssuedAt(new Date()) // Thời điểm tạo JWT
                .setExpiration(new Date(new Date().getTime() + 846000000)) // Thời điểm hết hạn của JWT (vd: 10 ngày)
                .claim("email", auth.getName()) // Thêm claim với key "email" và giá trị là tên đăng nhập
                .signWith(key).compact(); // Ký và compact chuỗi JWT

        return jwt; // Trả về chuỗi JWT đã tạo.
    }

    public String getEmailFromToken(String jwt) {
        // Loại bỏ tiền tố "Bearer " để lấy chuỗi JWT.
        jwt = jwt.substring(7);

        // Giải mã chuỗi JWT và lấy thông tin từ claims (payload).
        Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwt).getBody();

        // Lấy giá trị của claim "email" từ JWT, chứa tên đăng nhập.
        String email = String.valueOf(claims.get("email"));

        return email; // Trả về tên đăng nhập lấy từ JWT.
    }
}