package com.PassBanned.API.controller;


import com.PassBanned.API.Model.BannedPassenger;
import com.PassBanned.API.dto.BannedPassengerDto;
import com.PassBanned.API.service.BannedPassengerService;
import com.PassBanned.API.service.LocalFileStorageService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;
import java.util.Objects;

@RestController
@RequestMapping("/passengers")
public class BannedPassengerController {

    @Autowired
    private BannedPassengerService passengerService;

    @Autowired
    private LocalFileStorageService fileStorageService;

    @GetMapping
    public ResponseEntity<Page<BannedPassengerDto>> getAllPassengers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "banDate") String sortBy,
            @RequestParam(defaultValue = "desc") String sortDir) {
        
        Sort sort = sortDir.equalsIgnoreCase("desc") ? 
            Sort.by(sortBy).descending() : Sort.by(sortBy).ascending();
        Pageable pageable = PageRequest.of(page, size, sort);
        
        Page<BannedPassengerDto> passengers = passengerService.getAllPassengers(pageable);
        return ResponseEntity.ok(passengers);
    }

    @GetMapping("/{id}")
    public ResponseEntity<BannedPassengerDto> getPassengerById(@PathVariable Long id) {
        return passengerService.getPassengerById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/passport/{passportNumber}")
    public ResponseEntity<BannedPassengerDto> getPassengerByPassport(@PathVariable String passportNumber) {
        return passengerService.getPassengerByPassport(passportNumber)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public ResponseEntity<BannedPassengerDto> createPassenger(
            @Valid @RequestBody BannedPassengerDto passengerDto,
            Authentication authentication) {
        try {
            BannedPassengerDto createdPassenger = passengerService.createPassenger(
                passengerDto, authentication.getName());
            return ResponseEntity.status(HttpStatus.CREATED).body(createdPassenger);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    @PutMapping("/{id}")
    public ResponseEntity<BannedPassengerDto> updatePassenger(
            @PathVariable Long id, 
            @Valid @RequestBody BannedPassengerDto passengerDto) {
        try {
            BannedPassengerDto updatedPassenger = passengerService.updatePassenger(id, passengerDto);
            return ResponseEntity.ok(updatedPassenger);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deletePassenger(@PathVariable Long id) {
        try {
            passengerService.deletePassenger(id);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    @GetMapping("/search")
    public ResponseEntity<Page<BannedPassengerDto>> searchPassengers(
            @RequestParam String query,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        
        Pageable pageable = PageRequest.of(page, size);
        Page<BannedPassengerDto> passengers = passengerService.searchPassengers(query, pageable);
        return ResponseEntity.ok(passengers);
    }

    @GetMapping("/filter")
    public ResponseEntity<Page<BannedPassengerDto>> filterPassengers(
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String banDuration,
            @RequestParam(required = false) String nationality,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        
        BannedPassenger.Severity severityEnum = severity != null ?
            BannedPassenger.Severity.valueOf(severity.toUpperCase()) : null;
        BannedPassenger.Status statusEnum = status != null ? 
            BannedPassenger.Status.valueOf(status.toUpperCase()) : null;
        BannedPassenger.BanDuration banDurationEnum = banDuration != null ? 
            BannedPassenger.BanDuration.valueOf(banDuration.toUpperCase()) : null;
        
        Pageable pageable = PageRequest.of(page, size);
        Page<BannedPassengerDto> passengers = passengerService.findWithFilters(
            severityEnum, statusEnum, banDurationEnum, nationality, pageable);
        return ResponseEntity.ok(passengers);
    }

    @GetMapping("/recent")
    public ResponseEntity<List<BannedPassengerDto>> getRecentBans(
            @RequestParam(defaultValue = "7") int days) {
        List<BannedPassengerDto> recentBans = passengerService.getRecentBans(days);
        return ResponseEntity.ok(recentBans);
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Long>> getPassengerStats() {
        Map<String, Long> stats = Map.of(
            "totalPassengers", passengerService.getTotalPassengers(),
            "activeBans", passengerService.getActiveBans(),
            "criticalCases", passengerService.getCriticalCases()
        );
        return ResponseEntity.ok(stats);
    }

    @PostMapping("/image/upload")
    public ResponseEntity<Map<String, String>> uploadPassengerImage(
            @RequestParam("image") MultipartFile file,
            HttpServletRequest request) {
        try {
            if (file.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Fichier vide"));
            }
            if (!Objects.requireNonNull(file.getContentType()).startsWith("image/")) {
                return ResponseEntity.badRequest().body(Map.of("error", "Le fichier doit être une image"));
            }
            if (file.getSize() > 5 * 1024 * 1024) { // 5MB
                return ResponseEntity.badRequest().body(Map.of("error", "Le fichier ne doit pas dépasser 5MB"));
            }
            String imageUrl = fileStorageService.storeFile(file, request);
            return ResponseEntity.ok(Map.of("imageUrl", imageUrl, "url", imageUrl));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Erreur lors de l'upload: " + e.getMessage()));
        }
    }
}