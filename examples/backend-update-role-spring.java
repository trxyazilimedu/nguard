/**
 * Example Spring Boot Backend Controller for User Role Updates
 * Location: src/main/java/com/example/auth/controller/UserController.java
 *
 * This example shows how to:
 * 1. Receive role update requests from frontend
 * 2. Validate permissions
 * 3. Update user role in database
 * 4. Return updated user data
 * 5. Handle errors appropriately
 */

package com.example.auth.controller;

import com.example.auth.dto.UpdateRoleRequest;
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
public class UserController {

    private final UserService userService;

    /**
     * Update user role
     * Only admins can call this endpoint
     *
     * POST /api/users/{userId}/role
     *
     * Request Body:
     * {
     *   "role": "admin",
     *   "updatedBy": "admin-user-id"
     * }
     *
     * Response:
     * {
     *   "success": true,
     *   "message": "User role updated",
     *   "user": {
     *     "id": "user-123",
     *     "email": "user@example.com",
     *     "name": "John Doe",
     *     "role": "admin",
     *     "permissions": ["read", "write", "delete"]
     *   }
     * }
     */
    @PatchMapping("/{userId}/role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> updateUserRole(
            @PathVariable String userId,
            @Valid @RequestBody UpdateRoleRequest request,
            Authentication authentication) {

        try {
            log.info("User {} is updating role for user {}", authentication.getName(), userId);

            // Step 1: Get current user from authentication
            CustomUserDetails currentUser = (CustomUserDetails) authentication.getPrincipal();

            // Step 2: Validate the requested role
            if (!isValidRole(request.getRole())) {
                log.warn("Invalid role requested: {}", request.getRole());
                return ResponseEntity
                        .status(HttpStatus.BAD_REQUEST)
                        .body(errorResponse("Invalid role. Must be one of: USER, MODERATOR, ADMIN"));
            }

            // Step 3: Find the target user
            User targetUser = userService.findById(userId)
                    .orElseThrow(() -> {
                        log.warn("User not found with id: {}", userId);
                        return new NotFoundException("User not found");
                    });

            // Step 4: Prevent admin from removing their own admin role
            // (Optional security measure)
            if (userId.equals(currentUser.getId()) &&
                !request.getRole().equals("ADMIN") &&
                currentUser.getRole().equals("ADMIN")) {

                log.warn("Admin {} attempted to remove their own admin role", currentUser.getId());
                return ResponseEntity
                        .status(HttpStatus.FORBIDDEN)
                        .body(errorResponse("Cannot remove your own admin role"));
            }

            // Step 5: Update user role
            targetUser.setRole(request.getRole());
            User updatedUser = userService.save(targetUser);

            // Step 6: Log the audit action
            userService.createAuditLog(
                    currentUser.getId(),
                    "UPDATE_USER_ROLE",
                    String.format("Changed role from %s to %s for user %s",
                            targetUser.getRole(), request.getRole(), userId),
                    userId
            );

            // Step 7: Return success response with updated user
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "User role updated successfully");
            response.put("user", new UserResponse(updatedUser));

            log.info("Successfully updated role for user {} to {}", userId, request.getRole());
            return ResponseEntity.ok(response);

        } catch (NotFoundException e) {
            log.error("User not found: {}", userId);
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body(errorResponse(e.getMessage()));

        } catch (Exception e) {
            log.error("Error updating user role", e);
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(errorResponse("Failed to update user role"));
        }
    }

    /**
     * Get user by ID
     *
     * GET /api/users/{userId}
     */
    @GetMapping("/{userId}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getUser(@PathVariable String userId) {
        try {
            User user = userService.findById(userId)
                    .orElseThrow(() -> new NotFoundException("User not found"));

            return ResponseEntity.ok(new UserResponse(user));

        } catch (NotFoundException e) {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body(errorResponse(e.getMessage()));
        }
    }

    /**
     * List all users (admin only)
     *
     * GET /api/users
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> listUsers() {
        try {
            var users = userService.findAll();
            return ResponseEntity.ok(users.stream()
                    .map(UserResponse::new)
                    .toList());

        } catch (Exception e) {
            log.error("Error listing users", e);
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(errorResponse("Failed to list users"));
        }
    }

    // ============================================================================
    // Helper Methods
    // ============================================================================

    private boolean isValidRole(String role) {
        return role != null &&
               (role.equals("USER") ||
                role.equals("MODERATOR") ||
                role.equals("ADMIN"));
    }

    private Map<String, String> errorResponse(String message) {
        Map<String, String> response = new HashMap<>();
        response.put("error", message);
        return response;
    }
}
