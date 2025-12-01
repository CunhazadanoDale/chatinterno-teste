package com.athena.chat.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class FileUploadResponse {

    private boolean success;
    private String message;
    private String fileId;
    private String fileName;
    private String fileUrl;
    private Long fileSizeBytes;
    private String mimeType;

}
