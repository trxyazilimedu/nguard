/**
 * Example DTOs (Data Transfer Objects) for Backend
 * Location: src/main/java/com/example/auth/dto/
 */

// ============================================================================
// UpdateRoleRequest.java
// ============================================================================

package com.example.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request body for updating user role
 *
 * Example:
 * {
 *   "role": "admin",
 *   "updatedBy": "admin-user-id"
 * }
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UpdateRoleRequest {

    @NotBlank(message = "Role is required")
    private String role;

    private String updatedBy;  // Optional: track who made the change
}

// ============================================================================
// UpdatePreferencesRequest.java
// ============================================================================

package com.example.auth.dto;

import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request body for updating user preferences
 *
 * Example:
 * {
 *   "theme": "dark",
 *   "language": "tr",
 *   "notifications": true,
 *   "twoFactorEnabled": false
 * }
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UpdatePreferencesRequest {

    @Pattern(regexp = "light|dark", message = "Theme must be 'light' or 'dark'")
    private String theme;

    @Pattern(regexp = "en|tr", message = "Language must be 'en' or 'tr'")
    private String language;

    private Boolean notifications;

    private Boolean twoFactorEnabled;
}

// ============================================================================
// UserResponse.java
// ============================================================================

package com.example.auth.dto;

import com.example.auth.entity.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Response DTO for user data
 *
 * Example:
 * {
 *   "id": "user-123",
 *   "email": "user@example.com",
 *   "name": "John Doe",
 *   "role": "user",
 *   "permissions": ["read", "write"],
 *   "theme": "dark",
 *   "language": "tr",
 *   "notificationsEnabled": true,
 *   "twoFactorEnabled": false
 * }
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserResponse {
    private String id;
    private String email;
    private String name;
    private String role;
    private List<String> permissions;
    private String theme;
    private String language;
    private Boolean notificationsEnabled;
    private Boolean twoFactorEnabled;

    /**
     * Constructor from User entity
     */
    public UserResponse(User user) {
        this.id = user.getId();
        this.email = user.getEmail();
        this.name = user.getName();
        this.role = user.getRole();
        this.permissions = user.getPermissions(); // Assuming this is a method that returns List<String>
        this.theme = user.getTheme();
        this.language = user.getLanguage();
        this.notificationsEnabled = user.isNotificationsEnabled();
        this.twoFactorEnabled = user.isTwoFactorEnabled();
    }
}

// ============================================================================
// AuditLogRequest.java
// ============================================================================

package com.example.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request body for creating audit logs
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuditLogRequest {
    private String userId;
    private String action;
    private String details;
    private String targetUserId;
}

// ============================================================================
// ErrorResponse.java
// ============================================================================

package com.example.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.LocalDateTime;

/**
 * Standard error response format
 *
 * Example:
 * {
 *   "error": "User not found",
 *   "status": 404,
 *   "timestamp": "2024-01-15T10:30:00",
 *   "path": "/api/users/123"
 * }
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponse {
    private String error;
    private int status;
    private LocalDateTime timestamp;
    private String path;
    private String message;

    public static ErrorResponse of(String error, int status, String path) {
        return ErrorResponse.builder()
                .error(error)
                .status(status)
                .timestamp(LocalDateTime.now())
                .path(path)
                .build();
    }
}
