package com.athena.chat.controller.chat;

import com.athena.chat.config.SupabaseConfig;
import com.athena.chat.dto.FileUploadResponse;
import com.athena.chat.exceptions.FileUploadException;
import com.athena.chat.model.entities.User;
import com.athena.chat.services.storage.SupabaseStorageService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/files")
@RequiredArgsConstructor
@SecurityRequirement(name = "bearerAuth")
@Slf4j
public class FileUploadController {

    private final SupabaseStorageService supabaseStorageService;
    private final SupabaseConfig supabaseConfig;

    // Tipos de arquivo permitidos
    private static final List<String> ALLOWED_MIME_TYPES = Arrays.asList(
            // Documentos
            "application/pdf",
            "application/msword",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.ms-excel",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.ms-powerpoint",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "text/plain",
            // Imagens
            "image/jpeg",
            "image/png",
            "image/gif",
            "image/webp",
            // Outros
            "application/zip",
            "application/x-rar-compressed");

    /**
     * Endpoint para upload de arquivo
     */
    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<FileUploadResponse> uploadFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "folder", defaultValue = "chat-attachments") String folder,
            @AuthenticationPrincipal User userDetails) {

        try {
            // Validações
            validateFile(file);

            // Upload do arquivo
            String filePath = supabaseStorageService.uploadFile(file, folder);

            // Para buckets privados, a URL pública não funciona, mas retornamos o path
            // O frontend deve usar o endpoint /view para acessar
            String publicUrl = supabaseStorageService.getPublicUrl(filePath);

            // Criar resposta
            FileUploadResponse response = new FileUploadResponse(
                    true,
                    "Arquivo enviado com sucesso",
                    filePath,
                    file.getOriginalFilename(),
                    publicUrl,
                    file.getSize(),
                    file.getContentType());

            log.info("Usuário {} fez upload do arquivo: {}", userDetails.getUsername(), file.getOriginalFilename());
            return ResponseEntity.ok(response);

        } catch (FileUploadException e) {
            log.error("Erro ao fazer upload", e);
            FileUploadResponse errorResponse = new FileUploadResponse(
                    false,
                    e.getMessage(),
                    null,
                    null,
                    null,
                    null,
                    null);
            return ResponseEntity.badRequest().body(errorResponse);

        } catch (Exception e) {
            log.error("Erro inesperado ao fazer upload", e);
            FileUploadResponse errorResponse = new FileUploadResponse(
                    false,
                    "Erro interno ao processar arquivo",
                    null,
                    null,
                    null,
                    null,
                    null);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Endpoint para redirecionar para URL assinada (Secure View)
     */
    @GetMapping("/view")
    public ResponseEntity<Void> viewFile(@RequestParam("path") String path) {
        try {
            // Gera URL assinada válida por 1 hora
            String signedUrl = supabaseStorageService.getSignedUrl(path);

            // Redireciona o navegador para a URL assinada
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create(signedUrl))
                    .build();
        } catch (Exception e) {
            log.error("Erro ao gerar URL assinada para: {}", path, e);
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Upload de múltiplos arquivos
     */
    @PostMapping(value = "/upload/multiple", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<List<FileUploadResponse>> uploadMultipleFiles(
            @RequestParam("files") MultipartFile[] files,
            @RequestParam(value = "folder", defaultValue = "chat-attachments") String folder,
            @AuthenticationPrincipal User userDetails) {

        List<FileUploadResponse> responses = new ArrayList<>();

        for (MultipartFile file : files) {
            try {
                validateFile(file);

                String filePath = supabaseStorageService.uploadFile(file, folder);
                String publicUrl = supabaseStorageService.getPublicUrl(filePath);

                responses.add(new FileUploadResponse(
                        true,
                        "Arquivo enviado com sucesso",
                        filePath,
                        file.getOriginalFilename(),
                        publicUrl,
                        file.getSize(),
                        file.getContentType()));

            } catch (Exception e) {
                log.error("Erro ao fazer upload do arquivo: {}", file.getOriginalFilename(), e);
                responses.add(new FileUploadResponse(
                        false,
                        "Erro: " + e.getMessage(),
                        null,
                        file.getOriginalFilename(),
                        null,
                        null,
                        null));
            }
        }

        return ResponseEntity.ok(responses);
    }

    /**
     * Valida o arquivo antes do upload
     */
    private void validateFile(MultipartFile file) {
        // Verifica se o arquivo está vazio
        if (file.isEmpty()) {
            throw new FileUploadException("Arquivo vazio");
        }

        // Verifica o tamanho
        if (file.getSize() > supabaseConfig.getMaxFileSize()) {
            throw new FileUploadException(
                    String.format("Arquivo muito grande. Tamanho máximo: %d MB",
                            supabaseConfig.getMaxFileSize() / 1024 / 1024));
        }

        // Verifica o tipo MIME
        String contentType = file.getContentType();
        if (contentType == null || !ALLOWED_MIME_TYPES.contains(contentType)) {
            throw new FileUploadException("Tipo de arquivo não permitido: " + contentType);
        }

        // Verifica o nome do arquivo
        String filename = file.getOriginalFilename();
        if (filename == null || filename.contains("..")) {
            throw new FileUploadException("Nome de arquivo inválido");
        }
    }

}