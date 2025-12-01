package com.athena.chat.model.chat;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "anexos")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Anexo {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "mensagem_id")
    private Mensagem mensagem;

    @Column(nullable = false)
    private String nomeArquivo;

    @Column(nullable = false)
    private String tipoMime;

    @Column(nullable = false)
    private Long tamanhoBytes;

    @Column(nullable = false)
    private String caminhoSupabase;

    @Column(nullable = false, length = 2048)
    private String urlPublica;

    private LocalDateTime uploadedEm = LocalDateTime.now();

}
