package com.athena.chat.services.chat;

import com.athena.chat.dto.chat.ChatDTO;
import com.athena.chat.dto.chat.ChatResumoDTO;
import com.athena.chat.dto.chat.MensagemDTO;
import com.athena.chat.dto.mapper.ChatMapper;
import com.athena.chat.dto.mapper.MensagemMapper;
import com.athena.chat.dto.mapper.UserMapper;
import com.athena.chat.dto.simpledto.UserSimpleDTO;
import com.athena.chat.model.chat.Chat;
import com.athena.chat.model.chat.Mensagem;
import com.athena.chat.model.entities.Group;
import com.athena.chat.model.entities.User;
import com.athena.chat.model.entities.permissions.TipoChat;
import com.athena.chat.model.entities.permissions.UserRole;
import com.athena.chat.repositories.UserRepository;
import com.athena.chat.repositories.chat.ChatRepository;
import com.athena.chat.repositories.chat.MensagemRepository;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.annotation.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class ChatService {

    private final ChatRepository chatRepository;
    private final UserRepository userRepository;
    private final MensagemRepository mensagemRepository;


    public ChatDTO buscarPorId(Long id) {
        Chat chatId = chatRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Chat não encontrado com ID: " + id));

        return ChatMapper.toDTO(chatId);
    }

    public List<ChatDTO> listarTodos() {

        List<Chat> chatList = chatRepository.findAll();

        return chatList.stream()
                .map(ChatMapper::toDTO)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<ChatResumoDTO> listarChatsDoUsuario(Long userId) {
        List<Chat> chats = chatRepository.findByParticipantes_Id(userId);

        return chats.stream()
                .map(chat -> toChatResumo(chat, userId))
                // ordenar por data da ultima mensagem (nulls por último)
                .sorted(Comparator.comparing(
                        ChatResumoDTO::getUltimaMensagemEm,
                        Comparator.nullsLast(Comparator.reverseOrder())
                ))
                .collect(Collectors.toList());
    }

    private ChatResumoDTO toChatResumo(Chat chat, Long userId) {
        // última mensagem
        Mensagem ultima = chat.getMensagens().stream()
                .max(Comparator.comparing(Mensagem::getEnviadoEm))
                .orElse(null);

        String ultimoConteudo = ultima != null ? ultima.getConteudo() : null;
        LocalDateTime ultimaMensagemEm = ultima != null ? ultima.getEnviadoEm() : null;

        // não lidas pro usuário
        long naoLidas = 0L;
        if (ultima != null) {
            naoLidas = chat.getMensagens().stream()
                    .filter(m -> m.getUsuariosQueLeram().stream()
                            .noneMatch(u -> u.getId().equals(userId)))
                    .count();
        }

        // nome do “outro usuario” em chat privado
        String outroUsuario = null;
        if (chat.getTipo() == TipoChat.PRIVADO) {
            outroUsuario = chat.getParticipantes().stream()
                    .filter(u -> !u.getId().equals(userId))
                    .map(User::getNome)
                    .findFirst()
                    .orElse(chat.getNome());
        }

        // participantes em UserSimpleDTO
        List<UserSimpleDTO> participantes = chat.getParticipantes().stream()
                .map(UserMapper::toSimpleDTO)
                .collect(Collectors.toList());

        // pega o groupId se existir
        Long groupId = null;
        if (chat.getGrupo() != null) {
            groupId = chat.getGrupo().getId();
        }

        ChatResumoDTO dto = new ChatResumoDTO();
        dto.setId(chat.getId());
        dto.setGroupId(groupId);
        dto.setNome(chat.getNome());
        dto.setTipo(chat.getTipo());
        dto.setUltimoConteudo(ultimoConteudo);
        dto.setUltimaMensagemEm(ultimaMensagemEm);
        dto.setOutroUsuario(outroUsuario);
        dto.setQuantidadeNaoLidas(naoLidas);
        dto.setParticipantes(participantes);

        return dto;
    }

    @Transactional
    public MensagemDTO salvarMensagem(Long chatId, MensagemDTO dto, String emailUsuario) {
        Chat chat = chatRepository.findById(chatId)
                .orElseThrow(() -> new IllegalArgumentException("Chat não encontrado"));

        User remetente = userRepository.findByNome(emailUsuario)
                .orElseThrow(() -> new IllegalArgumentException("Usuário não autenticado"));

        Mensagem novaMensagem = MensagemMapper.fromDTO(dto, remetente, chat);

        Mensagem salva = mensagemRepository.save(novaMensagem);

        return MensagemMapper.toDTO(salva, remetente.getId());
    }

    @Transactional
    public ChatDTO criarChatPrivado(Long usuario1Id, Long usuario2Id) {

        // checa se ja existe algum chat entre os dois
        Optional<Chat> chatExistente = chatRepository
                .findChatPrivadoEntreUsuarios(usuario1Id, usuario2Id);

        // se existir, ele retorna o que existe entre od dois
        if (chatExistente.isPresent()) {
            return ChatMapper.toDTO(chatExistente.get());
        }

        // busca padrao pelos usuarios
        User user1 = userRepository.findById(usuario1Id)
                .orElseThrow(() -> new IllegalArgumentException("Usuário 1 não encontrado"));
        User user2 = userRepository.findById(usuario2Id)
                .orElseThrow(() -> new IllegalArgumentException("Usuário 2 não encontrado"));

        String nomeChat = user1.getNome() + " - " + user2.getNome();

        // monta grupo
        Group grupo = new Group();
        grupo.setNome(nomeChat);
        grupo.setDescricao("");
        grupo.setCriadoPor(user1);
        grupo.getMembros().add(user1);
        grupo.getMembros().add(user2);

        // monta chat
        Chat chat = new Chat();
        chat.setTipo(TipoChat.PRIVADO);
        chat.setNome(nomeChat);
        chat.getParticipantes().add(user1);
        chat.getParticipantes().add(user2);

        // liga os dois lados
        chat.setGrupo(grupo);
        grupo.setChat(chat);

        // salva so o CHAT (lado dono, com cascade = ALL)
        Chat salvo = chatRepository.save(chat);

        log.info("Chat privado criado: Chat={}, Grupo={}, Usuários={} e {}",
                salvo.getNome(), salvo.getGrupo().getNome(), user1.getNome(), user2.getNome());

        return ChatMapper.toDTO(salvo);
    }


    @Transactional
    public ChatDTO deletarChat(Long chatId, User autenticado) {
        Chat chat = chatRepository.findById(chatId)
                .orElseThrow(() -> new IllegalArgumentException("Chat não encontrado"));

        ChatDTO chatDTO = ChatMapper.toDTO(chat);
        Group grupo = chat.getGrupo();

        // se não tiver grupo vinculado, nao podemos deletar
        if (grupo == null) {
            throw new IllegalArgumentException("Chat não possui grupo associado");
        }

        User criador = grupo.getCriadoPor();

        if (criador == null) {
            throw new IllegalArgumentException("Grupo não possui criador definido");
        }

        boolean isCriador = criador.getId().equals(autenticado.getId());
        boolean isAdmin = autenticado.getRole() == UserRole.ADMIN;

        // se quiser que seja EXCLUSIVO do criador, tira o "|| isAdmin"
        if (!isCriador && !isAdmin) {
            throw new AccessDeniedException("Você não tem permissão para excluir este chat.");
        }

        // aqui é onde a mágica acontece:
        // Chat é o dono do @OneToOne(cascade = ALL, orphanRemoval = true) com Group.
        chatRepository.delete(chat);
        // -> deleta o Chat
        // -> cascade mata o Group
        // -> cascade em Mensagem (OneToMany) mata mensagens
        // -> ManyToMany com usuários limpa a join table

        return chatDTO;
    }

}
