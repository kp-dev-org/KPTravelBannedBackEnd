package com.PassBanned.API.service;

import com.PassBanned.API.Model.BannedPassenger;
import com.PassBanned.API.Model.User;
import com.PassBanned.API.dto.BannedPassengerDto;
import com.PassBanned.API.repository.BannedPassengerRepository;
import com.PassBanned.API.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@Transactional
public class BannedPassengerService {

    @Autowired
    private BannedPassengerRepository passengerRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuditLogService auditLogService;

    public List<BannedPassengerDto> getAllPassengers() {
        return passengerRepository.findAll().stream()
                .map(this::convertToDto)
                .collect(Collectors.toList());
    }


    public Page<BannedPassengerDto> getAllPassengers(Pageable pageable) {
        return passengerRepository.findAll(pageable)
                .map(this::convertToDto);
    }


    public Optional<BannedPassengerDto> getPassengerById(Long id) {
        return passengerRepository.findById(id)
                .map(this::convertToDto);
    }

    public Optional<BannedPassengerDto> getPassengerByPassport(String passportNumber) {
        return passengerRepository.findByPassportNumber(passportNumber)
                .map(this::convertToDto);
    }


    public BannedPassengerDto createPassenger(BannedPassengerDto passengerDto, String createdByEmail) {
        if (passengerRepository.existsByPassportNumber(passengerDto.getPassportNumber())) {
            throw new RuntimeException("Passenger with this passport number already exists");
        }

        User createdBy = userRepository.findByEmail(createdByEmail)
                .orElseThrow(() -> new RuntimeException("User not found"));

        BannedPassenger passenger = convertToEntity(passengerDto);
        passenger.setCreatedBy(createdBy);
        BannedPassenger savedPassenger = passengerRepository.save(passenger);

        try {
            auditLogService.record(
                "PASSENGER_CREATED",
                "PASSENGERS",
                "Enregistrement d'un passager interdit: " + savedPassenger.getFirstName() + " " + savedPassenger.getLastName() + " (Passeport: " + savedPassenger.getPassportNumber() + ")",
                createdByEmail,
                "Passenger #" + savedPassenger.getId(),
                "SUCCESS",
                null,
                "Gravité: " + savedPassenger.getSeverity() + ", Motif: " + savedPassenger.getBanReason()
            );
        } catch (Exception ignored) {}

        return convertToDto(savedPassenger);
    }

    public BannedPassengerDto updatePassenger(Long id, BannedPassengerDto passengerDto) {
        BannedPassenger passenger = passengerRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Passenger not found"));
        if (!passenger.getPassportNumber().equals(passengerDto.getPassportNumber()) &&
                passengerRepository.existsByPassportNumber(passengerDto.getPassportNumber())) {
            throw new RuntimeException("Passenger with this passport number already exists");
        }
        updateEntityFromDto(passenger, passengerDto);
        BannedPassenger updatedPassenger = passengerRepository.save(passenger);

        try {
            auditLogService.record(
                "PASSENGER_UPDATED",
                "PASSENGERS",
                "Mise à jour du passager interdit: " + updatedPassenger.getFirstName() + " " + updatedPassenger.getLastName() + " (Passeport: " + updatedPassenger.getPassportNumber() + ")",
                null,
                "Passenger #" + id,
                "SUCCESS",
                null,
                "Statut: " + updatedPassenger.getStatus() + ", Gravité: " + updatedPassenger.getSeverity()
            );
        } catch (Exception ignored) {}

        return convertToDto(updatedPassenger);
    }

    public void deletePassenger(Long id) {
        BannedPassenger passenger = passengerRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Passenger not found"));
        passengerRepository.deleteById(id);

        try {
            auditLogService.record(
                "PASSENGER_DELETED",
                "PASSENGERS",
                "Suppression de la fiche d'interdiction: " + passenger.getFirstName() + " " + passenger.getLastName() + " (Passeport: " + passenger.getPassportNumber() + ")",
                null,
                "Passenger #" + id,
                "WARNING",
                null,
                "Passeport: " + passenger.getPassportNumber()
            );
        } catch (Exception ignored) {}
    }

    public Page<BannedPassengerDto> searchPassengers(String query, Pageable pageable) {
        return passengerRepository.searchPassengers(query, pageable)
                .map(this::convertToDto);
    }


    public Page<BannedPassengerDto> findWithFilters(
            BannedPassenger.Severity severity,
            BannedPassenger.Status status,
            BannedPassenger.BanDuration banDuration,
            String nationality,
            Pageable pageable) {
        return passengerRepository.findWithFilters(severity, status, banDuration, nationality, pageable)
                .map(this::convertToDto);
    }

    public List<BannedPassengerDto> getRecentBans(int days) {
        LocalDate startDate = LocalDate.now().minusDays(days);
        return passengerRepository.findRecentBans(startDate).stream()
                .map(this::convertToDto)
                .collect(Collectors.toList());
    }

    public long getTotalPassengers() {
        return passengerRepository.count();
    }

    public long getActiveBans() {
        return passengerRepository.countActiveBans();
    }

    public long getCriticalCases() {
        return passengerRepository.countCriticalCases();
    }

    private BannedPassengerDto convertToDto(BannedPassenger passenger) {
        BannedPassengerDto dto = new BannedPassengerDto();
        dto.setId(passenger.getId());
        dto.setFirstName(passenger.getFirstName());
        dto.setLastName(passenger.getLastName());
        dto.setEmail(passenger.getEmail());
        dto.setPhone(passenger.getPhone());
        dto.setPassportNumber(passenger.getPassportNumber());
        dto.setPassportExpiryDate(passenger.getPassportExpiryDate());
        dto.setPassportIssuingCountry(passenger.getPassportIssuingCountry());
        dto.setNationality(passenger.getNationality());
        dto.setDateOfBirth(passenger.getDateOfBirth());
        dto.setBanReason(passenger.getBanReason());
        dto.setBanDate(passenger.getBanDate());
        dto.setBanDuration(passenger.getBanDuration());
        dto.setBanEndDate(passenger.getBanEndDate());
        dto.setSeverity(passenger.getSeverity());
        dto.setNotes(passenger.getNotes());
        dto.setStatus(passenger.getStatus());
        dto.setImageUrl(passenger.getImageUrl());
        dto.setCreatedByName(passenger.getCreatedBy().getName());   // Infos du créateur
        dto.setCreatedByEmail(passenger.getCreatedBy().getEmail());
        dto.setCreatedAt(passenger.getCreatedAt());
        dto.setUpdatedAt(passenger.getUpdatedAt());
        return dto;
    }

    private BannedPassenger convertToEntity(BannedPassengerDto dto) {
        BannedPassenger passenger = new BannedPassenger();
        updateEntityFromDto(passenger, dto);
        return passenger;
    }

    private void updateEntityFromDto(BannedPassenger passenger, BannedPassengerDto dto) {
        passenger.setFirstName(dto.getFirstName());
        passenger.setLastName(dto.getLastName());
        passenger.setEmail(dto.getEmail());
        passenger.setPhone(dto.getPhone());
        passenger.setPassportNumber(dto.getPassportNumber());
        passenger.setPassportExpiryDate(dto.getPassportExpiryDate());
        passenger.setPassportIssuingCountry(dto.getPassportIssuingCountry());
        passenger.setNationality(dto.getNationality());
        passenger.setDateOfBirth(dto.getDateOfBirth());
        passenger.setBanReason(dto.getBanReason());
        passenger.setBanDate(dto.getBanDate());
        passenger.setBanDuration(dto.getBanDuration());
        passenger.setBanEndDate(dto.getBanEndDate());
        passenger.setSeverity(dto.getSeverity());
        passenger.setNotes(dto.getNotes());
        passenger.setStatus(dto.getStatus());
        passenger.setImageUrl(dto.getImageUrl());
    }
}
