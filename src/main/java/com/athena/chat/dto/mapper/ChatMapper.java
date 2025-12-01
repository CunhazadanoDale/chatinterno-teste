package com.athena.chat.dto.mapper;

import com.athena.chat.dto.chat.ChatCreateDTO;
import com.athena.chat.dto.chat.ChatDTO;
import com.athena.chat.model.chat.Chat;

import java.util.stream.Collectors;

public class ChatMapper {

    public static ChatDTO toDTO(Chat chat) {
        Long groupId = null;

        if (chat.getGrupo() != null) {
            groupId = chat.getGrupo().getId();
        }

        return new ChatDTO(
                chat.getId(),
                groupId,
                chat.getNome(),
                chat.getParticipantes().stream()
                        .map(UserMapper::toSimpleDTO)
                        .collect(Collectors.toSet()),
                chat.getCriadoEm()
        );
    }

    public static Chat toEntity(ChatCreateDTO dto) {
        Chat chat = new Chat();
        chat.setNome(dto.getNome());
        // participantes serão setados no GroupService

        return chat;
    }
}
