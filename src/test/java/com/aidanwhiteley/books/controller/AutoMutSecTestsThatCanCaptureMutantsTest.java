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

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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

    // Mutant ID 6, 9: This test was created because the original test suite did not
    // capture this
    // ISIR mutation, which replaced the correct ROLE_ADMIN authority with an
    // invalid
    // role (NO_ROLE_ADMIN) in the authorization rule. This test verifies that a
    // properly authenticated admin user is still able to access the endpoint,
    // ensuring that breaking or altering the required administrative role is
    // detected
    // as a security regression.

    @Test
    void adminCanCreateABook() throws Exception {

        String token = jwtUtils.createTokenForUser(getTestUserAdmin());

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
                .andExpect(status().isCreated())
                .andDo(print());
    }

    // Mutant ID 10: This test case detects LNSO (Logical Negation Security
    // Operator) mutations
    // because it validates the expected positive authorization outcome for an
    // authenticated administrator. Any inversion of the security predicate results
    // in a denial of access, causing a mismatch between the expected HTTP 200
    // response and the mutated behavior (HTTP 403), thus revealing the security
    // regression

    @Test
    void adminCanAccessDebugHeaders() throws Exception {

        String token = jwtUtils.createTokenForUser(getTestUserAdmin());

        Cookie cookie = new Cookie(
                JwtAuthenticationService.JWT_COOKIE_NAME,
                token);

        mockMvc.perform(MockMvcRequestBuilders.get("/secure/api/debugheaders")
                .cookie(cookie)
                .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("headers:")))
                .andDo(print());
    }

    // Mutant ID 11: This test was created because the original test suite did not
    // capture this PARO mutation, which replaced the authorization rule with
    // permitAll(), effectively allowing any authenticated (or even unauthenticated)
    // user to access the endpoint.
    //
    // This test verifies that a user with the ROLE_EDITOR is correctly denied
    // access
    // to the endpoint protected by @PreAuthorize("hasRole('ROLE_ADMIN')").
    //
    // If the security constraint is weakened (e.g., replaced by permitAll), the
    // test
    // would incorrectly succeed, revealing a security regression by expecting
    // HTTP 403 Forbidden for non-admin users.

    @Test
    void editorCantAccessDebugHeaders() throws Exception {

        String token = jwtUtils.createTokenForUser(getTestUserEditor());

        Cookie cookie = new Cookie(
                JwtAuthenticationService.JWT_COOKIE_NAME,
                token);

        mockMvc.perform(MockMvcRequestBuilders.get("/secure/api/debugheaders")
                .cookie(cookie)
                .with(csrf()))
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

    public static User getTestUserAdmin() {
        User user = new User();
        user.setFullName(USER_WITH_ALL_ROLES_FULL_NAME);
        user.setAuthProvider(PROVIDER_ALL_ROLES_USER);
        user.setFirstLogon(LocalDateTime.now());
        user.setLastLogon(LocalDateTime.now());
        user.setEmail(DUMMY_EMAIL);

        user.setAuthenticationServiceId(USER_WITH_ALL_ROLES);
        user.addRole(User.Role.ROLE_ADMIN);

        return user;
    }

    public static User getTestUserEditor() {
        User user = new User();
        user.setFullName(USER_WITH_ALL_ROLES_FULL_NAME);
        user.setAuthProvider(PROVIDER_ALL_ROLES_USER);
        user.setFirstLogon(LocalDateTime.now());
        user.setLastLogon(LocalDateTime.now());
        user.setEmail(DUMMY_EMAIL);

        user.setAuthenticationServiceId(USER_WITH_ALL_ROLES);
        user.addRole(User.Role.ROLE_EDITOR);

        return user;
    }

}
