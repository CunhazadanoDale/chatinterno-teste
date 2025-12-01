package com.athena.chat.dto.chat;

import com.athena.chat.dto.simpledto.UserSimpleDTO;
import com.athena.chat.model.entities.permissions.TipoChat;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ChatResumoDTO {

    private Long id;
    private Long groupId;
    private String nome;
    private TipoChat tipo;

    // pra sidebar
    private String ultimoConteudo;
    private LocalDateTime ultimaMensagemEm;

    // pra privado: nome do outro usuário
    private String outroUsuario;

    // opcional pra badge de não lidas
    private Long quantidadeNaoLidas;

    // NOVO: participantes do chat
    private List<UserSimpleDTO> participantes;
}

