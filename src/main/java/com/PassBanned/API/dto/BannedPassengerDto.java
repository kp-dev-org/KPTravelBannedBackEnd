package com.PassBanned.API.dto;

import com.PassBanned.API.Model.BannedPassenger;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.LocalDate;
import java.time.LocalDateTime;

public class BannedPassengerDto {
    private Long id;
    
    @NotBlank
    @Size(max = 50)
    private String firstName;
    
    @NotBlank
    @Size(max = 50)
    private String lastName;
    
    @Email
    @Size(max = 100)
    private String email;
    
    @Size(max = 20)
    private String phone;
    
    @NotBlank
    @Size(max = 20)
    private String passportNumber;
    
    private LocalDate passportExpiryDate;

    @Size(max = 100)
    private String passportIssuingCountry;

    @NotBlank
    @Size(max = 50)
    private String nationality;
    
    @NotNull
    private LocalDate dateOfBirth;
    
    @NotBlank
    @Size(max = 1000)
    private String banReason;
    
    @NotNull
    private LocalDate banDate;
    
    private BannedPassenger.BanDuration banDuration;
    private LocalDate banEndDate;
    private BannedPassenger.Severity severity;
    private String notes;
    private BannedPassenger.Status status;
    private String imageUrl;
    private String createdByName;
    private String createdByEmail;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    // Constructors
    public BannedPassengerDto() {}

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getFirstName() { return firstName; }
    public void setFirstName(String firstName) { this.firstName = firstName; }

    public String getLastName() { return lastName; }
    public void setLastName(String lastName) { this.lastName = lastName; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getPhone() { return phone; }
    public void setPhone(String phone) { this.phone = phone; }

    public String getPassportNumber() { return passportNumber; }
    public void setPassportNumber(String passportNumber) { this.passportNumber = passportNumber; }

    public LocalDate getPassportExpiryDate() { return passportExpiryDate; }
    public void setPassportExpiryDate(LocalDate passportExpiryDate) { this.passportExpiryDate = passportExpiryDate; }

    public String getPassportIssuingCountry() { return passportIssuingCountry; }
    public void setPassportIssuingCountry(String passportIssuingCountry) { this.passportIssuingCountry = passportIssuingCountry; }

    public String getNationality() { return nationality; }
    public void setNationality(String nationality) { this.nationality = nationality; }

    public LocalDate getDateOfBirth() { return dateOfBirth; }
    public void setDateOfBirth(LocalDate dateOfBirth) { this.dateOfBirth = dateOfBirth; }

    public String getBanReason() { return banReason; }
    public void setBanReason(String banReason) { this.banReason = banReason; }

    public LocalDate getBanDate() { return banDate; }
    public void setBanDate(LocalDate banDate) { this.banDate = banDate; }

    public BannedPassenger.BanDuration getBanDuration() { return banDuration; }
    public void setBanDuration(BannedPassenger.BanDuration banDuration) { this.banDuration = banDuration; }

    public LocalDate getBanEndDate() { return banEndDate; }
    public void setBanEndDate(LocalDate banEndDate) { this.banEndDate = banEndDate; }

    public BannedPassenger.Severity getSeverity() { return severity; }
    public void setSeverity(BannedPassenger.Severity severity) { this.severity = severity; }

    public String getNotes() { return notes; }
    public void setNotes(String notes) { this.notes = notes; }

    public BannedPassenger.Status getStatus() { return status; }
    public void setStatus(BannedPassenger.Status status) { this.status = status; }

    public String getImageUrl() { return imageUrl; }
    public void setImageUrl(String imageUrl) { this.imageUrl = imageUrl; }

    public String getCreatedByName() { return createdByName; }
    public void setCreatedByName(String createdByName) { this.createdByName = createdByName; }

    public String getCreatedByEmail() { return createdByEmail; }
    public void setCreatedByEmail(String createdByEmail) { this.createdByEmail = createdByEmail; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
}