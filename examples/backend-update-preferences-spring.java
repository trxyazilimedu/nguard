/**
 * Example Spring Boot Backend Controller for User Preferences Update
 * Location: src/main/java/com/example/auth/controller/PreferencesController.java
 *
 * This example shows how to:
 * 1. Receive preference update requests from frontend
 * 2. Validate preference data
 * 3. Update user preferences in database
 * 4. Return success response
 * 5. Handle errors gracefully
 */

package com.example.auth.controller;

import com.example.auth.dto.UpdatePreferencesRequest;
import com.example.auth.dto.UserResponse;
import com.example.auth.entity.User;
import com.example.auth.service.UserService;
import com.example.auth.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class PreferencesController {

    private final UserService userService;

    /**
     * Update user preferences (theme, language, notifications, etc.)
     * Users can only update their own preferences
     *
     * PATCH /api/users/{userId}/preferences
     *
     * Request Body:
     * {
     *   "theme": "dark",
     *   "language": "tr",
     *   "notifications": true,
     *   "twoFactorEnabled": false
     * }
     *
     * Response:
     * {
     *   "success": true,
     *   "message": "Preferences updated successfully",
     *   "user": {
     *     "id": "user-123",
     *     "email": "user@example.com",
     *     "name": "John Doe",
     *     "role": "user",
     *     "theme": "dark",
     *     "language": "tr",
     *     "notificationsEnabled": true,
     *     "twoFactorEnabled": false
     *   }
     * }
     */
    @PatchMapping("/{userId}/preferences")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> updatePreferences(
            @PathVariable String userId,
            @Valid @RequestBody UpdatePreferencesRequest request,
            Authentication authentication) {

        try {
            log.info("User {} is updating preferences", authentication.getName());

            // Step 1: Get current user from authentication
            CustomUserDetails currentUser = (CustomUserDetails) authentication.getPrincipal();

            // Step 2: Users can only update their own preferences
            if (!userId.equals(currentUser.getId())) {
                log.warn("User {} attempted to update preferences for user {}",
                        currentUser.getId(), userId);
                return ResponseEntity
                        .status(HttpStatus.FORBIDDEN)
                        .body(errorResponse("You can only update your own preferences"));
            }

            // Step 3: Find the user
            User user = userService.findById(userId)
                    .orElseThrow(() -> {
                        log.warn("User not found with id: {}", userId);
                        return new NotFoundException("User not found");
                    });

            // Step 4: Validate theme value
            if (request.getTheme() != null && !isValidTheme(request.getTheme())) {
                log.warn("Invalid theme requested: {}", request.getTheme());
                return ResponseEntity
                        .status(HttpStatus.BAD_REQUEST)
                        .body(errorResponse("Invalid theme. Must be 'light' or 'dark'"));
            }

            // Step 5: Validate language value
            if (request.getLanguage() != null && !isValidLanguage(request.getLanguage())) {
                log.warn("Invalid language requested: {}", request.getLanguage());
                return ResponseEntity
                        .status(HttpStatus.BAD_REQUEST)
                        .body(errorResponse("Invalid language. Must be 'en' or 'tr'"));
            }

            // Step 6: Update preferences
            if (request.getTheme() != null) {
                user.setTheme(request.getTheme());
            }
            if (request.getLanguage() != null) {
                user.setLanguage(request.getLanguage());
            }
            if (request.getNotifications() != null) {
                user.setNotificationsEnabled(request.getNotifications());
            }
            if (request.getTwoFactorEnabled() != null) {
                user.setTwoFactorEnabled(request.getTwoFactorEnabled());
            }

            // Step 7: Save updated user
            User updatedUser = userService.save(user);

            // Step 8: Log the preference change
            Map<String, Object> changes = new HashMap<>();
            if (request.getTheme() != null) changes.put("theme", request.getTheme());
            if (request.getLanguage() != null) changes.put("language", request.getLanguage());
            if (request.getNotifications() != null) changes.put("notifications", request.getNotifications());
            if (request.getTwoFactorEnabled() != null) changes.put("twoFactorEnabled", request.getTwoFactorEnabled());

            userService.createAuditLog(
                    currentUser.getId(),
                    "UPDATE_PREFERENCES",
                    String.format("Updated preferences: %s", changes),
                    null
            );

            // Step 9: Return success response
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Preferences updated successfully");
            response.put("user", new UserResponse(updatedUser));

            log.info("Successfully updated preferences for user {}", userId);
            return ResponseEntity.ok(response);

        } catch (NotFoundException e) {
            log.error("User not found: {}", userId);
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body(errorResponse(e.getMessage()));

        } catch (Exception e) {
            log.error("Error updating preferences", e);
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(errorResponse("Failed to update preferences"));
        }
    }

    /**
     * Get user preferences
     *
     * GET /api/users/{userId}/preferences
     */
    @GetMapping("/{userId}/preferences")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getPreferences(
            @PathVariable String userId,
            Authentication authentication) {

        try {
            CustomUserDetails currentUser = (CustomUserDetails) authentication.getPrincipal();

            // Users can only see their own preferences
            if (!userId.equals(currentUser.getId())) {
                return ResponseEntity
                        .status(HttpStatus.FORBIDDEN)
                        .body(errorResponse("You can only view your own preferences"));
            }

            User user = userService.findById(userId)
                    .orElseThrow(() -> new NotFoundException("User not found"));

            Map<String, Object> preferences = new HashMap<>();
            preferences.put("theme", user.getTheme());
            preferences.put("language", user.getLanguage());
            preferences.put("notificationsEnabled", user.isNotificationsEnabled());
            preferences.put("twoFactorEnabled", user.isTwoFactorEnabled());

            return ResponseEntity.ok(preferences);

        } catch (NotFoundException e) {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body(errorResponse(e.getMessage()));

        } catch (Exception e) {
            log.error("Error getting preferences", e);
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(errorResponse("Failed to get preferences"));
        }
    }

    // ============================================================================
    // Helper Methods
    // ============================================================================

    private boolean isValidTheme(String theme) {
        return theme != null && (theme.equals("light") || theme.equals("dark"));
    }

    private boolean isValidLanguage(String language) {
        return language != null && (language.equals("en") || language.equals("tr"));
    }

    private Map<String, String> errorResponse(String message) {
        Map<String, String> response = new HashMap<>();
        response.put("error", message);
        return response;
    }
}
