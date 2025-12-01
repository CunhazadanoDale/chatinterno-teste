package com.athena.chat.dto.chat;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AnexoDTO {

    private Long id;
    private String nomeArquivo;
    private String tipoMime;
    private Long tamanhoBytes;
    private String urlPublica;
    private String caminhoSupabase; // ADICIONADO
    private String uploadedEm;
}