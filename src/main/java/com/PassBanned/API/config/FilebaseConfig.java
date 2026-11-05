package com.PassBanned.API.config;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Getter
@Configuration
public class FilebaseConfig {

    @Value("${supabase.url}")
    private String supabaseUrl;

    @Value("${supabase.key}")
    private String supabaseKey;

    @Value("${supabase.bucket}")
    private String bucketName;

    // 👉 Bean WebClient configuré pour ajouter automatiquement les headers
    @Bean
    public WebClient webClient(WebClient.Builder builder) {
        return builder
                .baseUrl(supabaseUrl)
                .defaultHeader("Authorization", "Bearer " + supabaseKey) // 🔑 Auth
                .defaultHeader("apikey", supabaseKey) // 🔑 Obligatoire pour Supabase
                .build();
    }

}
