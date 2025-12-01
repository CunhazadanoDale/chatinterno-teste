package com.athena.chat.dto.chat;

import lombok.Data;

import java.time.LocalDateTime;

@Data
public class NotificacaoDTO {
    private Long chatId;
    private String chatNome;
    private String conteudoResumo;
    private LocalDateTime enviadoEm;
}

