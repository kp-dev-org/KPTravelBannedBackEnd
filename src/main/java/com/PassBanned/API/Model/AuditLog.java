package com.PassBanned.API.Model;

import jakarta.persistence.*;
import lombok.Data;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Table(name = "audit_logs", indexes = {
    @Index(name = "idx_audit_timestamp", columnList = "timestamp"),
    @Index(name = "idx_audit_user_email", columnList = "user_email"),
    @Index(name = "idx_audit_action", columnList = "action"),
    @Index(name = "idx_audit_category", columnList = "category")
})
@EntityListeners(AuditingEntityListener.class)
@Data
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 100)
    private String action; // e.g. PASSENGER_CREATED, PASSENGER_DELETED, USER_LOGIN, MANIFEST_CHECK

    @Column(length = 50)
    private String category; // e.g. PASSENGERS, USERS, AUTH, SCREENING, SYSTEM

    @Column(nullable = false, length = 500)
    private String description;

    @Column(name = "user_email", length = 100)
    private String userEmail;

    @Column(name = "user_name", length = 100)
    private String userName;

    @Column(name = "user_role", length = 50)
    private String userRole;

    @Column(name = "target_resource", length = 150)
    private String targetResource;

    @Column(length = 30)
    private String status = "SUCCESS"; // SUCCESS, FAILURE, WARNING

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(columnDefinition = "TEXT")
    private String details;

    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime timestamp;

    public AuditLog() {
        this.timestamp = LocalDateTime.now();
    }

    public AuditLog(String action, String category, String description, String userEmail, 
                    String userName, String userRole, String targetResource, 
                    String status, String ipAddress, String details) {
        this.action = action;
        this.category = category;
        this.description = description;
        this.userEmail = userEmail;
        this.userName = userName;
        this.userRole = userRole;
        this.targetResource = targetResource;
        this.status = status != null ? status : "SUCCESS";
        this.ipAddress = ipAddress;
        this.details = details;
        this.timestamp = LocalDateTime.now();
    }
}
