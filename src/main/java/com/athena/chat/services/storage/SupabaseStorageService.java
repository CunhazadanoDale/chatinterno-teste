package com.athena.chat.services.storage;

import com.athena.chat.config.SupabaseConfig;
import com.athena.chat.exceptions.StorageException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.json.JSONObject;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class SupabaseStorageService {

    private final SupabaseConfig supabaseConfig;
    private final OkHttpClient httpClient = new OkHttpClient();

    /**
     * Faz upload de um arquivo para o Supabase Storage
     * 
     * @param file   Arquivo a ser enviado
     * @param folder Pasta dentro do bucket (ex: "chat-attachments", "avatars")
     * @return Caminho do arquivo no Supabase
     */
    public String uploadFile(MultipartFile file, String folder) {
        try {
            // Gerar nome único para o arquivo
            String fileName = generateUniqueFileName(file.getOriginalFilename());
            String filePath = folder + "/" + fileName;

            // Construir URL do Supabase Storage
            String url = String.format("%s/storage/v1/object/%s/%s",
                    supabaseConfig.getUrl(),
                    supabaseConfig.getBucket().getName(),
                    filePath);

            // Criar request body
            RequestBody requestBody = RequestBody.create(
                    file.getBytes(),
                    MediaType.parse(file.getContentType()));

            // Criar request
            Request request = new Request.Builder()
                    .url(url)
                    .post(requestBody)
                    .addHeader("Authorization", "Bearer " + supabaseConfig.getServicekey())
                    .addHeader("Content-Type", file.getContentType())
                    .build();

            // Executar request
            try (Response response = httpClient.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    String errorBody = response.body() != null ? response.body().string() : "Unknown error";
                    log.error("Erro ao fazer upload: {}", errorBody);
                    throw new StorageException("Falha ao fazer upload do arquivo: " + errorBody);
                }

                log.info("Arquivo enviado com sucesso: {}", filePath);
                return filePath;
            }

        } catch (IOException e) {
            log.error("Erro ao fazer upload do arquivo", e);
            throw new StorageException("Erro ao fazer upload do arquivo", e);
        }
    }

    /**
     * Gera URL pública para um arquivo
     * 
     * @param filePath Caminho do arquivo no bucket
     * @return URL pública
     */
    public String getPublicUrl(String filePath) {
        return String.format("%s/storage/v1/object/public/%s/%s",
                supabaseConfig.getUrl(),
                supabaseConfig.getBucket().getName(),
                filePath);
    }

    /**
     * Gera URL assinada temporária para download (válida por 1 hora)
     * 
     * @param filePath Caminho do arquivo no bucket
     * @return URL assinada
     */
    public String getSignedUrl(String filePath) {
        try {
            String url = String.format("%s/storage/v1/object/sign/%s/%s",
                    supabaseConfig.getUrl(),
                    supabaseConfig.getBucket().getName(),
                    filePath);

            JSONObject jsonBody = new JSONObject();
            jsonBody.put("expiresIn", 3600);

            RequestBody requestBody = RequestBody.create(
                    jsonBody.toString(),
                    MediaType.parse("application/json"));

            Request request = new Request.Builder()
                    .url(url)
                    .post(requestBody)
                    .addHeader("Authorization", "Bearer " + supabaseConfig.getServicekey())
                    .addHeader("Content-Type", "application/json")
                    .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    throw new StorageException("Falha ao gerar URL assinada");
                }

                String responseBody = response.body().string();
                JSONObject jsonResponse = new JSONObject(responseBody);
                String signedUrlPath = jsonResponse.getString("signedURL");

                // CORREÇÃO: Garantir que a URL final tenha o prefixo correto
                // Se o caminho retornado não começar com /storage/v1, adicionamos manualmente
                if (!signedUrlPath.startsWith("/storage/v1")) {
                    // Se começar com /, remove para não duplicar
                    if (signedUrlPath.startsWith("/")) {
                        signedUrlPath = "/storage/v1" + signedUrlPath;
                    } else {
                        signedUrlPath = "/storage/v1/" + signedUrlPath;
                    }
                }

                // Removemos qualquer barra final da URL base para evitar duplicação
                String baseUrl = supabaseConfig.getUrl();
                if (baseUrl.endsWith("/")) {
                    baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
                }

                return baseUrl + signedUrlPath;
            }

        } catch (IOException e) {
            log.error("Erro ao gerar URL assinada", e);
            throw new StorageException("Erro ao gerar URL assinada", e);
        }
    }

    /**
     * Deleta um arquivo do Supabase Storage
     * 
     * @param filePath Caminho do arquivo no bucket
     */
    public void deleteFile(String filePath) {
        try {
            String url = String.format("%s/storage/v1/object/%s/%s",
                    supabaseConfig.getUrl(),
                    supabaseConfig.getBucket().getName(),
                    filePath);

            Request request = new Request.Builder()
                    .url(url)
                    .delete()
                    .addHeader("Authorization", "Bearer " + supabaseConfig.getServicekey())
                    .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    log.warn("Falha ao deletar arquivo: {}", filePath);
                }
            }

        } catch (IOException e) {
            log.error("Erro ao deletar arquivo", e);
            throw new StorageException("Erro ao deletar arquivo", e);
        }
    }

    /**
     * Gera nome único para arquivo
     */
    private String generateUniqueFileName(String originalFilename) {
        String extension = "";
        if (originalFilename != null && originalFilename.contains(".")) {
            extension = originalFilename.substring(originalFilename.lastIndexOf("."));
        }
        return UUID.randomUUID().toString() + extension;
    }

}
