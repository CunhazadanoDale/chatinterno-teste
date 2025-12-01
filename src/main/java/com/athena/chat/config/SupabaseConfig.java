package com.athena.chat.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "supabase")
@Data
public class SupabaseConfig {

    private String url;
    private String servicekey;
    private Bucket bucket = new Bucket();
    private Long maxFileSize = 10485760L; // 10MB default

    @Data
    public static class Bucket {
        private String name = "mensagens-arquivos";
    }

}
