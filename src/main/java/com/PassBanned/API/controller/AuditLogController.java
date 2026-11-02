package com.PassBanned.API.controller;

import com.PassBanned.API.Model.AuditLog;
import com.PassBanned.API.service.AuditLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/audit-logs")
public class AuditLogController {

    @Autowired
    private AuditLogService auditLogService;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<AuditLog>> getAuditLogs(
            @RequestParam(required = false) String query,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime startDate,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime endDate,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size,
            @RequestParam(defaultValue = "timestamp") String sortBy,
            @RequestParam(defaultValue = "desc") String sortDir) {

        Sort sort = sortDir.equalsIgnoreCase("asc") ? Sort.by(sortBy).ascending() : Sort.by(sortBy).descending();
        Pageable pageable = PageRequest.of(page, size, sort);

        Page<AuditLog> result = auditLogService.searchLogs(query, category, status, startDate, endDate, pageable);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/recent")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<AuditLog>> getRecentAuditLogs() {
        return ResponseEntity.ok(auditLogService.getRecentLogs());
    }

    @GetMapping("/stats")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getAuditStats() {
        return ResponseEntity.ok(auditLogService.getAuditStats());
    }

    @PostMapping
    public ResponseEntity<AuditLog> recordClientLog(
            @RequestBody Map<String, String> payload,
            Authentication authentication) {
        String email = authentication != null ? authentication.getName() : payload.get("userEmail");
        String action = payload.getOrDefault("action", "OPERATION_PERFORMED");
        String category = payload.getOrDefault("category", "SYSTEM");
        String description = payload.getOrDefault("description", "Opération enregistrée");
        String targetResource = payload.get("targetResource");
        String status = payload.getOrDefault("status", "SUCCESS");
        String ipAddress = payload.get("ipAddress");
        String details = payload.get("details");

        AuditLog saved = auditLogService.record(action, category, description, email, targetResource, status, ipAddress, details);
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }
}
