package com.PassBanned.API.service;

import com.PassBanned.API.config.FilebaseConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.io.IOException;
import java.util.UUID;

@Service
public class SupabaseStorageService {

    @Autowired
    private FilebaseConfig supabaseConfig;

    @Autowired
    private WebClient supabaseWebClient;

    public String uploadAvatar(MultipartFile file, String userId) throws IOException {
        // Générer un nom de fichier unique
        String fileExtension = getFileExtension(file.getOriginalFilename());
        String fileName = "avatar-" + userId + "-" + System.currentTimeMillis() + "." + fileExtension;
        String filePath = "avatars/" + fileName;

        try {
            // Préparer les données du fichier
            ByteArrayResource fileResource = new ByteArrayResource(file.getBytes()) {
                @Override
                public String getFilename() {
                    return fileName;
                }
            };

            // Upload vers Supabase Storage
            String response = supabaseWebClient
                    .post()
                    .uri("/storage/v1/object/" + supabaseConfig.getBucketName() + "/" + filePath)
                    .header(HttpHeaders.CONTENT_TYPE, file.getContentType())
                    .body(BodyInserters.fromResource(fileResource))
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            // Retourner l'URL publique
            return supabaseConfig.getSupabaseUrl() +
                    "/storage/v1/object/public/" +
                    supabaseConfig.getBucketName() + "/" +
                    filePath;

        } catch (WebClientResponseException e) {
            throw new IOException("Erreur lors de l'upload vers Supabase: " + e.getMessage());
        } catch (Exception e) {
            throw new IOException("Erreur lors de l'upload: " + e.getMessage());
        }
    }

    public String uploadAvatarForNewUser(MultipartFile file) throws IOException {
        // Générer un nom unique basé sur UUID + timestamp
        String fileExtension = getFileExtension(file.getOriginalFilename());
        String uniqueId = UUID.randomUUID().toString();
        String fileName = "avatar-new-" + uniqueId + "-" + System.currentTimeMillis() + "." + fileExtension;

        // Ici, le chemin de fichier est relatif au bucket (donc SANS reboucler avatars/avatars)
        String filePath = "avatars/" + fileName;  // avatars = dossier dans ton bucket

        try {
            // Créer une ressource binaire à partir du fichier uploadé
            ByteArrayResource fileResource = new ByteArrayResource(file.getBytes()) {
                @Override
                public String getFilename() {
                    return fileName;
                }
            };

            // Effectuer la requête POST vers Supabase Storage
            supabaseWebClient
                    .post()
                    .uri("/storage/v1/object/" + supabaseConfig.getBucketName() + "/" + filePath)
                    .header(HttpHeaders.CONTENT_TYPE, file.getContentType())
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + supabaseConfig.getSupabaseKey()) // ✅ clé secrète côté serveur
                    .header("apikey", supabaseConfig.getSupabaseKey()) // ✅ obligatoire aussi
                    .body(BodyInserters.fromResource(fileResource))
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            // Retourner l’URL publique
            return supabaseConfig.getSupabaseUrl() +
                    "/storage/v1/object/public/" +
                    supabaseConfig.getBucketName() + "/" +
                    filePath;

        } catch (WebClientResponseException e) {
            // Log complet pour debug
            throw new IOException("Erreur lors de l'upload vers Supabase: " +
                    e.getRawStatusCode() + " " + e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new IOException("Erreur lors de upload: " + e.getMessage(), e);
        }
    }


    public String uploadPassengerImage(MultipartFile file) throws IOException {
        String fileExtension = getFileExtension(file.getOriginalFilename());
        String uniqueId = UUID.randomUUID().toString();
        String fileName = "passenger-" + uniqueId + "-" + System.currentTimeMillis() + "." + fileExtension;
        String filePath = "passengers/" + fileName;

        try {
            ByteArrayResource fileResource = new ByteArrayResource(file.getBytes()) {
                @Override
                public String getFilename() {
                    return fileName;
                }
            };

            supabaseWebClient
                    .post()
                    .uri("/storage/v1/object/" + supabaseConfig.getBucketName() + "/" + filePath)
                    .header(HttpHeaders.CONTENT_TYPE, file.getContentType())
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + supabaseConfig.getSupabaseKey())
                    .header("apikey", supabaseConfig.getSupabaseKey())
                    .body(BodyInserters.fromResource(fileResource))
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            return supabaseConfig.getSupabaseUrl() +
                    "/storage/v1/object/public/" +
                    supabaseConfig.getBucketName() + "/" +
                    filePath;

        } catch (WebClientResponseException e) {
            throw new IOException("Erreur lors de l'upload vers Supabase: " +
                    e.getRawStatusCode() + " " + e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new IOException("Erreur lors de upload: " + e.getMessage(), e);
        }
    }

    private String getFileExtension(String filename) {
        if (filename == null || filename.lastIndexOf('.') == -1) {
            return "jpg";
        }
        return filename.substring(filename.lastIndexOf('.') + 1).toLowerCase();
    }

    public void deleteAvatar(String avatarUrl) {
        if (avatarUrl == null || !avatarUrl.contains(supabaseConfig.getSupabaseUrl())) {
            return; // Pas un fichier Supabase
        }

        try {
            // Extraire le chemin du fichier depuis l'URL
            String publicPath = "/storage/v1/object/public/" + supabaseConfig.getBucketName() + "/";
            int pathIndex = avatarUrl.indexOf(publicPath);
            if (pathIndex == -1) {
                return;
            }

            String filePath = avatarUrl.substring(pathIndex + publicPath.length());

            // Supprimer le fichier
            supabaseWebClient
                    .delete()
                    .uri("/storage/v1/object/" + supabaseConfig.getBucketName() + "/" + filePath)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

        } catch (Exception e) {
            System.err.println("Erreur lors de la suppression de l'avatar: " + e.getMessage());
        }
    }
}