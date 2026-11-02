package com.PassBanned.API.Model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Table(name = "banned_passengers")
@EntityListeners(AuditingEntityListener.class) // Permet la gestion automatique des dates (createdAt, updatedAt)
@Data
@NoArgsConstructor
@AllArgsConstructor
public class BannedPassenger {


    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Size(max = 50) // Limite la longueur
    @Column(name = "first_name", nullable = false)
    private String firstName;

    @NotBlank
    @Size(max = 50)
    @Column(name = "last_name", nullable = false)
    private String lastName;

    @Email
    @Size(max = 100)
    @Column
    private String email;

    @Size(max = 20)
    @Column
    private String phone;

    @NotBlank
    @Size(max = 20)
    @Column(name = "passport_number", nullable = false, unique = true)
    private String passportNumber;

    @NotBlank
    @Size(max = 50)
    @Column(nullable = false)
    private String nationality;

    @NotNull
    @Column(name = "date_of_birth", nullable = false)
    private LocalDate dateOfBirth;

    @NotBlank
    @Size(max = 1000)
    @Column(name = "ban_reason", nullable = false)
    private String banReason;

    @NotNull
    @Column(name = "ban_date", nullable = false)
    private LocalDate banDate;

    @Enumerated(EnumType.STRING)
    @Column(name = "ban_duration", nullable = false)
    private BanDuration banDuration = BanDuration.TEMPORARY;

    @Column(name = "ban_end_date")
    private LocalDate banEndDate;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Severity severity = Severity.MEDIUM;

    @Column(columnDefinition = "TEXT")
    private String notes;

    @Column(name = "image_url", length = 500)
    private String imageUrl;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Status status = Status.ACTIVE;


    @ManyToOne(fetch = FetchType.LAZY) // Plusieurs passagers peuvent être créés par un même utilisateur
    @JoinColumn(name = "created_by_id", nullable = false) // Colonne clé étrangère
    private User createdBy;

    // ----- Dates automatiques -----
    @CreatedDate // Rempli automatiquement lors de la création
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate // Mis à jour automatiquement lors d'une modification
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;


    public enum BanDuration {
        TEMPORARY, PERMANENT
    }


    public enum Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    public enum Status {
        ACTIVE, EXPIRED, UNDER_REVIEW
    }
}
