package com.PassBanned.API.config;


import com.PassBanned.API.Model.BannedPassenger;
import com.PassBanned.API.Model.User;
import com.PassBanned.API.repository.BannedPassengerRepository;
import com.PassBanned.API.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BannedPassengerRepository passengerRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        // Create default users if they don't exist
        User admin = new User();
        // Admin user (flyasky.com)
        if (userRepository.findByEmail("eabi@flyasky.com").isEmpty()) {
            admin.setName("Administrateur Asky");
            admin.setEmail("eabi@flyasky.com");
            admin.setPassword(passwordEncoder.encode("admin123"));
            admin.setRole(User.Role.ADMIN);
            admin.setStatus(User.Status.ACTIVE);
            admin.setAvatarUrl("https://images.pexels.com/photos/2379004/pexels-photo-2379004.jpeg?auto=compress&cs=tinysrgb&w=150&h=150&dpr=1");
            admin.setLastLogin(LocalDateTime.now());
            userRepository.save(admin);
        }

        // Regular user (flyasky.com)
        if (userRepository.findByEmail("user@flyasky.com").isEmpty()) {
            User user = new User();
            user.setName("Utilisateur Asky");
            user.setEmail("user@flyasky.com");
            user.setPassword(passwordEncoder.encode("user123"));
            user.setRole(User.Role.USER);
            user.setStatus(User.Status.ACTIVE);
            user.setAvatarUrl("https://images.pexels.com/photos/3763188/pexels-photo-3763188.jpeg?auto=compress&cs=tinysrgb&w=150&h=150&dpr=1");
            user.setLastLogin(LocalDateTime.now().minusDays(1));
            userRepository.save(user);
        }

        // Legacy admin@asky.com if missing
        if (userRepository.findByEmail("admin@asky.com").isEmpty()) {
            User legacyAdmin = new User();
            legacyAdmin.setName("Administrateur Principal");
            legacyAdmin.setEmail("admin@asky.com");
            legacyAdmin.setPassword(passwordEncoder.encode("admin123"));
            legacyAdmin.setRole(User.Role.ADMIN);
            legacyAdmin.setStatus(User.Status.ACTIVE);
            legacyAdmin.setLastLogin(LocalDateTime.now());
            userRepository.save(legacyAdmin);
        }

            // Create sample banned passengers
            createSamplePassengers(admin);

    }

    private void createSamplePassengers(User createdBy) {
        // Passenger 1
        BannedPassenger passenger1 = new BannedPassenger();
        passenger1.setFirstName("Jean");
        passenger1.setLastName("Dupont");
        passenger1.setEmail("jean.dupont@email.com");
        passenger1.setPhone("+33 1 23 45 67 89");
        passenger1.setPassportNumber("FR123456789");
        passenger1.setNationality("Française");
        passenger1.setDateOfBirth(LocalDate.of(1985, 3, 15));
        passenger1.setBanReason("Comportement agressif envers le personnel");
        passenger1.setBanDate(LocalDate.of(2024, 1, 15));
        passenger1.setBanDuration(BannedPassenger.BanDuration.TEMPORARY);
        passenger1.setBanEndDate(LocalDate.of(2024, 7, 15));
        passenger1.setSeverity(BannedPassenger.Severity.HIGH);
        passenger1.setNotes("Incident grave lors du vol AF1234. Menaces verbales.");
        passenger1.setStatus(BannedPassenger.Status.ACTIVE);
        passenger1.setCreatedBy(createdBy);
        passengerRepository.save(passenger1);

        // Passenger 2
        BannedPassenger passenger2 = new BannedPassenger();
        passenger2.setFirstName("Marie");
        passenger2.setLastName("Martin");
        passenger2.setEmail("marie.martin@email.com");
        passenger2.setPhone("+33 2 34 56 78 90");
        passenger2.setPassportNumber("FR987654321");
        passenger2.setNationality("Française");
        passenger2.setDateOfBirth(LocalDate.of(1990, 7, 22));
        passenger2.setBanReason("Consommation excessive d'alcool");
        passenger2.setBanDate(LocalDate.of(2024, 2, 1));
        passenger2.setBanDuration(BannedPassenger.BanDuration.PERMANENT);
        passenger2.setSeverity(BannedPassenger.Severity.MEDIUM);
        passenger2.setNotes("Récidiviste. Plusieurs incidents documentés.");
        passenger2.setStatus(BannedPassenger.Status.ACTIVE);
        passenger2.setCreatedBy(createdBy);
        passengerRepository.save(passenger2);

        // Passenger 3
        BannedPassenger passenger3 = new BannedPassenger();
        passenger3.setFirstName("Ahmed");
        passenger3.setLastName("Hassan");
        passenger3.setEmail("ahmed.hassan@email.com");
        passenger3.setPhone("+212 6 12 34 56 78");
        passenger3.setPassportNumber("MA123456789");
        passenger3.setNationality("Marocaine");
        passenger3.setDateOfBirth(LocalDate.of(1978, 11, 8));
        passenger3.setBanReason("Tentative d'embarquement avec documents falsifiés");
        passenger3.setBanDate(LocalDate.of(2024, 1, 20));
        passenger3.setBanDuration(BannedPassenger.BanDuration.PERMANENT);
        passenger3.setSeverity(BannedPassenger.Severity.CRITICAL);
        passenger3.setNotes("Fraude documentaire. Cas transmis aux autorités.");
        passenger3.setStatus(BannedPassenger.Status.ACTIVE);
        passenger3.setCreatedBy(createdBy);
        passengerRepository.save(passenger3);

        BannedPassenger passenger4 = new BannedPassenger();
        passenger4.setFirstName("Jean");
        passenger4.setLastName("Dupont");
        passenger4.setEmail("jean2.dupont@email.com");
        passenger4.setPhone("+33 6 45 67 89 12");
        passenger4.setPassportNumber("FR9876543213");
        passenger4.setNationality("Française");
        passenger4.setDateOfBirth(LocalDate.of(1985, 3, 15));
        passenger4.setBanReason("Trouble à l'ordre public dans l'aéroport");
        passenger4.setBanDate(LocalDate.of(2023, 12, 5));
        passenger4.setBanDuration(BannedPassenger.BanDuration.TEMPORARY);
        passenger4.setSeverity(BannedPassenger.Severity.HIGH);
        passenger4.setNotes("Incident grave nécessitant intervention de la police.");
        passenger4.setStatus(BannedPassenger.Status.ACTIVE);
        passenger4.setCreatedBy(createdBy);
        passengerRepository.save(passenger4);

        BannedPassenger passenger5 = new BannedPassenger();
        passenger5.setFirstName("Fatou");
        passenger5.setLastName("Diop");
        passenger5.setEmail("fatou3.diop@email.com");
        passenger5.setPhone("+221 77 123 45 67");
        passenger5.setPassportNumber("SN112233445");
        passenger5.setNationality("Sénégalaise");
        passenger5.setDateOfBirth(LocalDate.of(1990, 7, 20));
        passenger5.setBanReason("Refus d’obtempérer aux consignes de sécurité");
        passenger5.setBanDate(LocalDate.of(2024, 2, 10));
        passenger5.setBanDuration(BannedPassenger.BanDuration.TEMPORARY);
        passenger5.setSeverity(BannedPassenger.Severity.MEDIUM);
        passenger5.setNotes("Comportement irrespectueux avec l’équipage.");
        passenger5.setStatus(BannedPassenger.Status.ACTIVE);
        passenger5.setCreatedBy(createdBy);
        passengerRepository.save(passenger5);

        BannedPassenger passenger6 = new BannedPassenger();
        passenger6.setFirstName("Mohamed");
        passenger6.setLastName("Ali");
        passenger6.setEmail("mohamed1.ali@email.com");
        passenger6.setPhone("+20 100 234 5678");
        passenger6.setPassportNumber("EG445566778");
        passenger6.setNationality("Égyptienne");
        passenger6.setDateOfBirth(LocalDate.of(1972, 6, 3));
        passenger6.setBanReason("Tentative de voyager avec un passeport expiré");
        passenger6.setBanDate(LocalDate.of(2024, 3, 12));
        passenger6.setBanDuration(BannedPassenger.BanDuration.TEMPORARY);
        passenger6.setSeverity(BannedPassenger.Severity.LOW);
        passenger6.setNotes("Documents non valides au contrôle.");
        passenger6.setStatus(BannedPassenger.Status.ACTIVE);
        passenger6.setCreatedBy(createdBy);
        passengerRepository.save(passenger6);

        BannedPassenger passenger7 = new BannedPassenger();
        passenger7.setFirstName("Sara");
        passenger7.setLastName("Lopez");
        passenger7.setEmail("sara.lopez@email.com");
        passenger7.setPhone("+34 612 345 678");
        passenger7.setPassportNumber("ES556677889");
        passenger7.setNationality("Espagnole");
        passenger7.setDateOfBirth(LocalDate.of(1995, 10, 9));
        passenger7.setBanReason("Transport de substances interdites");
        passenger7.setBanDate(LocalDate.of(2023, 11, 30));
        passenger7.setBanDuration(BannedPassenger.BanDuration.PERMANENT);
        passenger7.setSeverity(BannedPassenger.Severity.CRITICAL);
        passenger7.setNotes("Cas transmis aux autorités judiciaires.");
        passenger7.setStatus(BannedPassenger.Status.ACTIVE);
        passenger7.setCreatedBy(createdBy);
        passengerRepository.save(passenger7);

        BannedPassenger passenger8 = new BannedPassenger();
        passenger8.setFirstName("David");
        passenger8.setLastName("Smith");
        passenger8.setEmail("david.smith@email.com");
        passenger8.setPhone("+44 7700 900123");
        passenger8.setPassportNumber("UK223344556");
        passenger8.setNationality("Britannique");
        passenger8.setDateOfBirth(LocalDate.of(1982, 5, 25));
        passenger8.setBanReason("Agressions verbales répétées");
        passenger8.setBanDate(LocalDate.of(2024, 1, 2));
        passenger8.setBanDuration(BannedPassenger.BanDuration.TEMPORARY);
        passenger8.setSeverity(BannedPassenger.Severity.HIGH);
        passenger8.setNotes("Menace l'équipage, nécessitant assistance.");
        passenger8.setStatus(BannedPassenger.Status.ACTIVE);
        passenger8.setCreatedBy(createdBy);
        passengerRepository.save(passenger8);

        BannedPassenger passenger9 = new BannedPassenger();
        passenger9.setFirstName("Amina");
        passenger9.setLastName("Ouedraogo");
        passenger9.setEmail("amina.ouedraogo@email.com");
        passenger9.setPhone("+226 70 12 34 56");
        passenger9.setPassportNumber("BF998877665");
        passenger9.setNationality("Burkinabè");
        passenger9.setDateOfBirth(LocalDate.of(1988, 9, 12));
        passenger9.setBanReason("Tentative de fraude à l’embarquement");
        passenger9.setBanDate(LocalDate.of(2024, 2, 14));
        passenger9.setBanDuration(BannedPassenger.BanDuration.PERMANENT);
        passenger9.setSeverity(BannedPassenger.Severity.CRITICAL);
        passenger9.setNotes("Intervention des autorités requise.");
        passenger9.setStatus(BannedPassenger.Status.ACTIVE);
        passenger9.setCreatedBy(createdBy);
        passengerRepository.save(passenger9);

        BannedPassenger passenger10 = new BannedPassenger();
        passenger10.setFirstName("Lucas");
        passenger10.setLastName("Martinez");
        passenger10.setEmail("lucas.martinez@email.com");
        passenger10.setPhone("+54 9 11 2345 6789");
        passenger10.setPassportNumber("AR445577889");
        passenger10.setNationality("Argentin");
        passenger10.setDateOfBirth(LocalDate.of(1993, 2, 18));
        passenger10.setBanReason("Usage de fausse identité");
        passenger10.setBanDate(LocalDate.of(2023, 12, 15));
        passenger10.setBanDuration(BannedPassenger.BanDuration.PERMANENT);
        passenger10.setSeverity(BannedPassenger.Severity.CRITICAL);
        passenger10.setNotes("Identité usurpée détectée.");
        passenger10.setStatus(BannedPassenger.Status.ACTIVE);
        passenger10.setCreatedBy(createdBy);
        passengerRepository.save(passenger10);


        BannedPassenger passenger11 = new BannedPassenger();
        passenger11.setFirstName("Issa");
        passenger11.setLastName("Traoré");
        passenger11.setEmail("issa.traore@email.com");
        passenger11.setPhone("+223 70 12 34 56");
        passenger11.setPassportNumber("ML123654987");
        passenger11.setNationality("Malian");
        passenger11.setDateOfBirth(LocalDate.of(1990, 9, 21));
        passenger11.setBanReason("Importation illégale de substances interdites");
        passenger11.setBanDate(LocalDate.of(2022, 11, 5));
        passenger11.setBanDuration(BannedPassenger.BanDuration.PERMANENT);
        passenger11.setSeverity(BannedPassenger.Severity.CRITICAL);
        passenger11.setNotes("Saisie de produits prohibés par la douane.");
        passenger11.setStatus(BannedPassenger.Status.ACTIVE);
        passenger11.setCreatedBy(createdBy);
        passengerRepository.save(passenger11);

        BannedPassenger passenger12 = new BannedPassenger();
        passenger12.setFirstName("Mariam");
        passenger12.setLastName("Sylla");
        passenger12.setEmail("mariam.sylla@email.com");
        passenger12.setPhone("+225 01 23 45 67");
        passenger12.setPassportNumber("CI456789123");
        passenger12.setNationality("Ivoirienne");
        passenger12.setDateOfBirth(LocalDate.of(1995, 3, 30));
        passenger12.setBanReason("Usage de faux passeport");
        passenger12.setBanDate(LocalDate.of(2024, 3, 12));
        passenger12.setBanDuration(BannedPassenger.BanDuration.PERMANENT);
        passenger12.setSeverity(BannedPassenger.Severity.HIGH);
        passenger12.setNotes("Passeport falsifié détecté à l’embarquement.");
        passenger12.setStatus(BannedPassenger.Status.ACTIVE);
        passenger12.setCreatedBy(createdBy);
        passengerRepository.save(passenger12);

        BannedPassenger passenger13 = new BannedPassenger();
        passenger13.setFirstName("Fatou");
        passenger13.setLastName("Diallo");
        passenger13.setEmail("fatou.diallo@email.com");
        passenger13.setPhone("+224 66 77 88 99");
        passenger13.setPassportNumber("GN789654123");
        passenger13.setNationality("Guinéenne");
        passenger13.setDateOfBirth(LocalDate.of(1987, 12, 1));
        passenger13.setBanReason("Tentative de corruption du personnel");
        passenger13.setBanDate(LocalDate.of(2023, 9, 25));
        passenger13.setBanDuration(BannedPassenger.BanDuration.PERMANENT);
        passenger13.setSeverity(BannedPassenger.Severity.HIGH);
        passenger13.setNotes("A tenté de soudoyer un agent de sécurité.");
        passenger13.setStatus(BannedPassenger.Status.ACTIVE);
        passenger13.setCreatedBy(createdBy);
        passengerRepository.save(passenger13);

        BannedPassenger passenger14 = new BannedPassenger();
        passenger14.setFirstName("Jean");
        passenger14.setLastName("Dupont");
        passenger14.setEmail("jean.dupont@email.com");
        passenger14.setPhone("+33 6 12 34 56 78");
        passenger14.setPassportNumber("FR654987321");
        passenger14.setNationality("Française");
        passenger14.setDateOfBirth(LocalDate.of(1972, 5, 17));
        passenger14.setBanReason("Voyage avec billets frauduleux");
        passenger14.setBanDate(LocalDate.of(2022, 10, 10));
        passenger14.setBanDuration(BannedPassenger.BanDuration.PERMANENT);
        passenger14.setSeverity(BannedPassenger.Severity.MEDIUM);
        passenger14.setNotes("Billets obtenus via un réseau frauduleux.");
        passenger14.setStatus(BannedPassenger.Status.ACTIVE);
        passenger14.setCreatedBy(createdBy);
        passengerRepository.save(passenger14);

        BannedPassenger passenger15 = new BannedPassenger();
        passenger15.setFirstName("Ousmane");
        passenger15.setLastName("Cissé");
        passenger15.setEmail("ousmane.cisse@email.com");
        passenger15.setPhone("+221 77 88 99 00");
        passenger15.setPassportNumber("SN321654987");
        passenger15.setNationality("Sénégalaise");
        passenger15.setDateOfBirth(LocalDate.of(1993, 6, 14));
        passenger15.setBanReason("Violence physique sur un passager");
        passenger15.setBanDate(LocalDate.of(2023, 1, 28));
        passenger15.setBanDuration(BannedPassenger.BanDuration.PERMANENT);
        passenger15.setSeverity(BannedPassenger.Severity.CRITICAL);
        passenger15.setNotes("Intervention de la police nécessaire.");
        passenger15.setStatus(BannedPassenger.Status.ACTIVE);
        passenger15.setCreatedBy(createdBy);
        passengerRepository.save(passenger15);

        BannedPassenger passenger16 = new BannedPassenger();
        passenger16.setFirstName("Sophia");
        passenger16.setLastName("Martinez");
        passenger16.setEmail("sophia.martinez@email.com");
        passenger16.setPhone("+34 612 345 678");
        passenger16.setPassportNumber("ES123987456");
        passenger16.setNationality("Espagnole");
        passenger16.setDateOfBirth(LocalDate.of(1980, 4, 5));
        passenger16.setBanReason("Refus répété de respecter les consignes de sécurité");
        passenger16.setBanDate(LocalDate.of(2021, 6, 9));
        passenger16.setBanDuration(BannedPassenger.BanDuration.TEMPORARY);
        passenger16.setSeverity(BannedPassenger.Severity.LOW);
        passenger16.setNotes("Comportement perturbateur à bord.");
        passenger16.setStatus(BannedPassenger.Status.EXPIRED);
        passenger16.setCreatedBy(createdBy);
        passengerRepository.save(passenger16);

        BannedPassenger passenger17 = new BannedPassenger();
        passenger17.setFirstName("Kofi");
        passenger17.setLastName("Mensah");
        passenger17.setEmail("kofi.mensah@email.com");
        passenger17.setPhone("+233 24 56 78 90");
        passenger17.setPassportNumber("GH654321987");
        passenger17.setNationality("Ghanéenne");
        passenger17.setDateOfBirth(LocalDate.of(1988, 7, 19));
        passenger17.setBanReason("Transport de substances illicites");
        passenger17.setBanDate(LocalDate.of(2023, 4, 15));
        passenger17.setBanDuration(BannedPassenger.BanDuration.PERMANENT);
        passenger17.setSeverity(BannedPassenger.Severity.CRITICAL);
        passenger17.setNotes("Condamnation judiciaire confirmée.");
        passenger17.setStatus(BannedPassenger.Status.ACTIVE);
        passenger17.setCreatedBy(createdBy);
        passengerRepository.save(passenger17);

        BannedPassenger passenger18 = new BannedPassenger();
        passenger18.setFirstName("Hawa");
        passenger18.setLastName("Konaté");
        passenger18.setEmail("hawa.konate@email.com");
        passenger18.setPhone("+223 78 90 12 34");
        passenger18.setPassportNumber("ML852963741");
        passenger18.setNationality("Maliane");
        passenger18.setDateOfBirth(LocalDate.of(1999, 8, 22));
        passenger18.setBanReason("Tentative d’usurpation d’identité");
        passenger18.setBanDate(LocalDate.of(2024, 2, 8));
        passenger18.setBanDuration(BannedPassenger.BanDuration.PERMANENT);
        passenger18.setSeverity(BannedPassenger.Severity.HIGH);
        passenger18.setNotes("Identité falsifiée détectée lors du contrôle.");
        passenger18.setStatus(BannedPassenger.Status.ACTIVE);
        passenger18.setCreatedBy(createdBy);
        passengerRepository.save(passenger18);

        BannedPassenger passenger19 = new BannedPassenger();
        passenger19.setFirstName("Ali");
        passenger19.setLastName("Mohamed");
        passenger19.setEmail("ali.mohamed@email.com");
        passenger19.setPhone("+20 100 234 567");
        passenger19.setPassportNumber("EG741852963");
        passenger19.setNationality("Égyptienne");
        passenger19.setDateOfBirth(LocalDate.of(1976, 10, 11));
        passenger19.setBanReason("Refus de paiement d’amendes récurrentes");
        passenger19.setBanDate(LocalDate.of(2022, 12, 2));
        passenger19.setBanDuration(BannedPassenger.BanDuration.PERMANENT);
        passenger19.setSeverity(BannedPassenger.Severity.MEDIUM);
        passenger19.setNotes("Multiples infractions non régularisées.");
        passenger19.setStatus(BannedPassenger.Status.ACTIVE);
        passenger19.setCreatedBy(createdBy);
        passengerRepository.save(passenger19);

        BannedPassenger passenger20 = new BannedPassenger();
        passenger20.setFirstName("Leila");
        passenger20.setLastName("Ben Ali");
        passenger20.setEmail("leila.benali@email.com");
        passenger20.setPhone("+216 22 33 44 55");
        passenger20.setPassportNumber("TN963258741");
        passenger20.setNationality("Tunisienne");
        passenger20.setDateOfBirth(LocalDate.of(1992, 1, 6));
        passenger20.setBanReason("Voyage avec visa falsifié");
        passenger20.setBanDate(LocalDate.of(2023, 5, 14));
        passenger20.setBanDuration(BannedPassenger.BanDuration.PERMANENT);
        passenger20.setSeverity(BannedPassenger.Severity.HIGH);
        passenger20.setNotes("Découverte lors du contrôle des documents.");
        passenger20.setStatus(BannedPassenger.Status.ACTIVE);
        passenger20.setCreatedBy(createdBy);
        passengerRepository.save(passenger20);

    }
}