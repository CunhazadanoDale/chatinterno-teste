package com.athena.chat.services.chat;

import com.athena.chat.dto.chat.MensagemDTO;
import com.athena.chat.dto.mapper.MensagemMapper;
import com.athena.chat.model.chat.Chat;
import com.athena.chat.model.chat.Mensagem;
import com.athena.chat.model.entities.User;
import com.athena.chat.repositories.UserRepository;
import com.athena.chat.repositories.chat.ChatRepository;
import com.athena.chat.repositories.chat.MensagemRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class MensagemService {

    private final MensagemRepository mensagemRepository;
    private final UserRepository userRepository;
    private final ChatRepository chatRepository;

    @Transactional
    public MensagemDTO salvarMensagem(Long chatId, MensagemDTO dto, String nomeUsuario) {
        Chat chat = chatRepository.findById(chatId)
                .orElseThrow(() -> new IllegalArgumentException("Chat não encontrado"));

        User remetente = userRepository.findByNome(nomeUsuario)
                .orElseThrow(() -> new IllegalArgumentException("Usuário não autenticado"));

        // ADICIONAR VALIDAÇÃO
        if (!chat.getParticipantes().contains(remetente)) {
            try {
                throw new IllegalAccessException("Usuário não é participante deste chat");
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        }

        dto.setRemetenteId(remetente.getId());
        Mensagem novaMensagem = MensagemMapper.fromDTO(dto, remetente, chat);
        Mensagem salva = mensagemRepository.save(novaMensagem);

        return MensagemMapper.toDTO(salva, remetente.getId());
    }

    @Transactional
    public List<MensagemDTO> listarMensagensPaginado(Long chatId, Long userId, int page, int size) {

        User usuario = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        // pega últimas mensagens primeiro (DESC)
        PageRequest pageable = PageRequest.of(page, size);
        Page<Mensagem> pageMensagens =
                mensagemRepository.findByChatIdOrderByEnviadoEmDesc(chatId, pageable);

        List<Mensagem> mensagens = pageMensagens.getContent();

        // marca como lidas APENAS as que vieram nessa página
        for (Mensagem m : mensagens) {
            boolean jaLeu = m.getUsuariosQueLeram().stream()
                    .anyMatch(u -> u.getId().equals(userId));
            if (!jaLeu) {
                m.getUsuariosQueLeram().add(usuario);
            }
        }
        mensagemRepository.saveAll(mensagens);

        // devolve pro front em ordem cronológica (ASC)
        return mensagens.stream()
                .sorted(Comparator.comparing(Mensagem::getEnviadoEm))
                .map(m -> MensagemMapper.toDTO(m, userId))
                .collect(Collectors.toList());
    }

}

