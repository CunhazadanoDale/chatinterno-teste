package com.athena.chat.dto.chat;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class MensagemDTO {
    private Long id;
    private Long chatId;
    private Long remetenteId;
    private String remetenteNome;
    private String conteudo;
    private LocalDateTime enviadoEm;
    private boolean lida; // true se o usuário atual ja leu
    private List<AnexoDTO> anexos = new ArrayList<>();
}
