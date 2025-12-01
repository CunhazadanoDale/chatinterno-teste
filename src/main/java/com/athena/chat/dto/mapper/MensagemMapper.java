package com.athena.chat.dto.mapper;

import com.athena.chat.dto.chat.AnexoDTO;
import com.athena.chat.dto.chat.MensagemDTO;
import com.athena.chat.dto.chat.SimpleMensagemDTO;
import com.athena.chat.model.chat.Anexo;
import com.athena.chat.model.chat.Chat;
import com.athena.chat.model.chat.Mensagem;
import com.athena.chat.model.entities.User;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class MensagemMapper {

    public static MensagemDTO toDTO(Mensagem mensagem, Long userId) {
        boolean lida;
        if (mensagem.getRemetente().getId().equals(userId)) {
            lida = mensagem.getUsuariosQueLeram().stream()
                    .anyMatch(u -> !u.getId().equals(userId));
        } else {
            lida = mensagem.getUsuariosQueLeram().stream()
                    .anyMatch(u -> u.getId().equals(userId));
        }

        MensagemDTO dto = new MensagemDTO();
        dto.setId(mensagem.getId());
        dto.setChatId(mensagem.getChat().getId());
        dto.setRemetenteId(mensagem.getRemetente().getId());
        dto.setRemetenteNome(mensagem.getRemetente().getNome());
        dto.setConteudo(mensagem.getConteudo());
        dto.setEnviadoEm(mensagem.getEnviadoEm());
        dto.setLida(lida);

        if (mensagem.getAnexos() != null && !mensagem.getAnexos().isEmpty()) {
            List<AnexoDTO> anexosDTO = mensagem.getAnexos().stream()
                    .map(MensagemMapper::anexoToDTO)
                    .collect(Collectors.toList());
            dto.setAnexos(anexosDTO);
        }

        return dto;
    }

    public static Mensagem fromDTO(MensagemDTO dto, User remetente, Chat chat) {
        Mensagem mensagem = new Mensagem();
        mensagem.setChat(chat);
        mensagem.setRemetente(remetente);
        mensagem.setConteudo(dto.getConteudo());
        mensagem.setEnviadoEm(LocalDateTime.now());

        mensagem.getUsuariosQueLeram().add(remetente);

        // CORREÇÃO: Mapear e salvar anexos
        if (dto.getAnexos() != null && !dto.getAnexos().isEmpty()) {
            List<Anexo> anexos = dto.getAnexos().stream()
                    .map(anexoDto -> {
                        Anexo anexo = new Anexo();
                        anexo.setNomeArquivo(anexoDto.getNomeArquivo());
                        anexo.setTipoMime(anexoDto.getTipoMime());
                        anexo.setTamanhoBytes(anexoDto.getTamanhoBytes());
                        anexo.setUrlPublica(anexoDto.getUrlPublica());
                        anexo.setCaminhoSupabase(anexoDto.getCaminhoSupabase()); // Importante!
                        anexo.setMensagem(mensagem); // Vínculo bidirecional
                        return anexo;
                    })
                    .collect(Collectors.toList());

            mensagem.setAnexos(anexos);
        }

        return mensagem;
    }

    public static SimpleMensagemDTO dtoToSimpleDto(MensagemDTO mensagem) {
        SimpleMensagemDTO simpleMensagemDTO = new SimpleMensagemDTO();
        simpleMensagemDTO.setChatId(mensagem.getChatId());
        simpleMensagemDTO.setNomeEnvio(mensagem.getRemetenteNome());
        simpleMensagemDTO.setConteudo(mensagem.getConteudo());
        return simpleMensagemDTO;
    }

    private static AnexoDTO anexoToDTO(Anexo anexo) {
        AnexoDTO dto = new AnexoDTO();
        dto.setId(anexo.getId());
        dto.setNomeArquivo(anexo.getNomeArquivo());
        dto.setTipoMime(anexo.getTipoMime());
        dto.setTamanhoBytes(anexo.getTamanhoBytes());
        dto.setUrlPublica(anexo.getUrlPublica());
        dto.setCaminhoSupabase(anexo.getCaminhoSupabase()); // ADICIONADO
        if (anexo.getUploadedEm() != null) {
            dto.setUploadedEm(anexo.getUploadedEm().format(DateTimeFormatter.ISO_DATE_TIME));
        }
        return dto;
    }
}