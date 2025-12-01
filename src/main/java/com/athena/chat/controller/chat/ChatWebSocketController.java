package com.athena.chat.controller.chat;

import com.athena.chat.dto.chat.MensagemDTO;
import com.athena.chat.dto.chat.NotificacaoDTO;
import com.athena.chat.model.chat.Chat;
import com.athena.chat.model.entities.User;
import com.athena.chat.repositories.UserRepository;
import com.athena.chat.repositories.chat.ChatRepository;
import com.athena.chat.services.chat.ChatService;
import lombok.RequiredArgsConstructor;
import org.springframework.messaging.handler.annotation.DestinationVariable;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;

import java.security.Principal;

@RequiredArgsConstructor
@Controller
public class ChatWebSocketController {

    private final SimpMessagingTemplate messagingTemplate;
    private final ChatService chatService;
    private final UserRepository userRepository;
    private final ChatRepository chatRepository; // <-- injeta

    @Transactional
    @MessageMapping("/chats/{chatId}/send")
    public void enviarMensagem(
            @DestinationVariable Long chatId,
            MensagemDTO mensagemDTO,
            Principal principal) {

        try {
            String nomeUsuario;

            if (principal != null) {
                String emailUsuario = principal.getName();
                System.out.println("✅ Email do usuário recebido: " + emailUsuario);

                User usuarioEncontrado = userRepository.findByEmail(emailUsuario)
                        .orElseThrow(() -> new IllegalArgumentException("Usuário não encontrado"));

                nomeUsuario = usuarioEncontrado.getNome();
                System.out.println("✅ Nome do usuário: " + nomeUsuario);

            } else if (mensagemDTO.getRemetenteNome() != null && !mensagemDTO.getRemetenteNome().isEmpty()) {
                nomeUsuario = mensagemDTO.getRemetenteNome();
                System.out.println("⚠️ Usando fallback remetenteNome: " + nomeUsuario);
            } else {
                throw new IllegalArgumentException("Usuário não identificado");
            }

            System.out.println("📨 Salvando mensagem para chat: " + chatId + " de: " + nomeUsuario);
            MensagemDTO mensagemSalva = chatService.salvarMensagem(chatId, mensagemDTO, nomeUsuario);
            System.out.println("✅ Mensagem salva com sucesso: " + mensagemSalva.getId());

            // 1) envia para o tópico do chat (como o @SendTo fazia)
            messagingTemplate.convertAndSend(
                    "/topic/chats/" + chatId,
                    mensagemSalva
            );

            // 2) busca o chat para pegar participantes
            Chat chat = chatRepository.findById(chatId)
                    .orElseThrow(() -> new IllegalArgumentException("Chat não encontrado"));

            // 3) monta notificação e envia para cada participante (menos o remetente)
            chat.getParticipantes().forEach(participante -> {
                if (participante.getId().equals(mensagemSalva.getRemetenteId())) {
                    return; // não notifica quem mandou
                }

                NotificacaoDTO notif = new NotificacaoDTO();
                notif.setChatId(chatId);
                notif.setChatNome(chat.getNome());
                notif.setConteudoResumo(mensagemSalva.getConteudo());
                notif.setEnviadoEm(mensagemSalva.getEnviadoEm());

                messagingTemplate.convertAndSend(
                        "/topic/users/" + participante.getId(),
                        notif
                );
            });

        } catch (Exception e) {
            System.err.println("❌ Erro ao enviar mensagem: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
}
