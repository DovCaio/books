package com.aidanwhiteley.books.controller;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import com.aidanwhiteley.books.controller.jwt.JwtAuthenticationService;
import com.aidanwhiteley.books.domain.Book;
import com.aidanwhiteley.books.util.BookTestUtils;
import com.aidanwhiteley.books.controller.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.aidanwhiteley.books.domain.User;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;

import jakarta.servlet.http.Cookie;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.Collections;

@SpringBootTest
@AutoConfigureMockMvc
public class AutoMutSecTestsThatCanCaptureMutantsTest {

    public static final String USER_WITH_ALL_ROLES_FULL_NAME = "Joe Dimagio";
    public static final String USER_WITH_EDITOR_ROLE_FULL_NAME = "Babe Ruth";
    public static final String ANOTHER_USER_WITH_EDITOR_ROLE_FULL_NAME = "Brian Lara";
    public static final String DUMMY_EMAIL = "joe.dimagio@gmail.com";
    public static final String DR_ZEUSS = "Dr Zuess";
    public static final String J_UNIT_TESTING_FOR_BEGINNERS = "JUnit testing for beginners";
    public static final String A_GUIDE_TO_POKING_SOFTWARE = "A guide to poking software";
    public static final String COMPUTING = "Computing";
    private static final String USER_WITH_ALL_ROLES = "107641999401234521888";
    private static final String USER_WITH_EDITOR_ROLE = "1632142143412347";
    private static final String ANOTHER_USER_WITH_EDITOR_ROLE = "111222333444555666";
    private static final User.AuthenticationProvider PROVIDER_ALL_ROLES_USER = User.AuthenticationProvider.GOOGLE;
    private static final User.AuthenticationProvider PROVIDER_EDITOR_USER = User.AuthenticationProvider.FACEBOOK;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private ObjectMapper objectMapper;

    // Mutant ID 2: This test was created because the original test suite did not
    // capture this
    // PARO mutation, which replaced the authorization rule with permitAll(). This
    // test verifies
    // that users without the required roles cannot access the endpoint, ensuring
    // that relaxing
    // the authorization constraint is detected as a security regression.

    @Test
    void userRoleCannotCreateBook() throws Exception {

        String token = jwtUtils.createTokenForUser(getTestUserUser());

        Cookie cookie = new Cookie(
                JwtAuthenticationService.JWT_COOKIE_NAME,
                token);

        Book book = Book.builder()
                .title("Test Book")
                .author("Test Author")
                .genre("Fantasy")
                .summary("Test summary")
                .rating(Book.Rating.GOOD)
                .build();

        mockMvc.perform(MockMvcRequestBuilders.post("/secure/api/books")
                .cookie(cookie)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(book)))
                .andExpect(status().isForbidden())
                .andDo(print());
    }

    public static User getTestUserUser() {
        User user = new User();
        user.setFullName(USER_WITH_ALL_ROLES_FULL_NAME);
        user.setAuthProvider(PROVIDER_ALL_ROLES_USER);
        user.setFirstLogon(LocalDateTime.now());
        user.setLastLogon(LocalDateTime.now());
        user.setEmail(DUMMY_EMAIL);

        user.setAuthenticationServiceId(USER_WITH_ALL_ROLES);
        user.addRole(User.Role.ROLE_USER);

        return user;
    }

}
