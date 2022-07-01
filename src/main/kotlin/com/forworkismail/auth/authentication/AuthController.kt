package com.forworkismail.auth.authentication

import com.forworkismail.auth.user.User
import com.forworkismail.auth.user.UserService
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.CookieValue
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.util.*
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletResponse


@RestController
@RequestMapping("/api/v1/auth")
class AuthController @Autowired constructor(val userService: UserService) {

    @PostMapping("/register")
    fun register(@RequestBody body: RegisterDTO): ResponseEntity<User> {
        val user = User()
        user.email = body.email
        user.name = body.name
        user.password = body.password
        return ResponseEntity.ok(userService.save(user))
    }

    @PostMapping("/login")
    fun login(@RequestBody body: LoginDTO, response: HttpServletResponse): ResponseEntity<Any> {
        val user = userService.findByEmail(body.email)
        if (user == null || !(user.comparePassword(body.password))) {
            return ResponseEntity.badRequest().body(Message("User not found!"))
        }

        val issuer = user.id.toString()
        val key = Keys.hmacShaKeyFor("wefwghehravd124324tuidhgs89wsdf@234".toByteArray())
        val jwt = Jwts.builder()
                .setIssuer(issuer)
                .setExpiration(Date(System.currentTimeMillis() + (60 * 24 * 1000)))
                .signWith(key)
                .compact()

        val cookie = Cookie("jwt", jwt)
        cookie.isHttpOnly = true

        response.addCookie(cookie)

        return ResponseEntity.ok(Message("Login success!"))
    }

    @GetMapping("user")
    fun user(@CookieValue("jwt") jwt: String?): ResponseEntity<Any> {
        try {
            if (jwt == null) {
                return ResponseEntity.status(401).body(Message("Unauthorized"))
            }

            val body = Jwts.parser().setSigningKey(Keys.hmacShaKeyFor("wefwghehravd124324tuidhgs89wsdf@234".toByteArray())).parseClaimsJws(jwt).body
            val user = userService.findById(UUID.fromString(body.issuer))
            return ResponseEntity.ok(user)

        } catch (e: Exception) {
            return ResponseEntity.status(401).body(Message("Unauthorized"))
        }
    }

    @PostMapping("logout")
    fun logout(response: HttpServletResponse): ResponseEntity<Any> {
        val cookie = Cookie("jwt", "")
        cookie.isHttpOnly = true
        cookie.maxAge = 0
        response.addCookie(cookie)
        return ResponseEntity.ok(Message("Logout success!"))
    }

}