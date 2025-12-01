package com.athena.chat.controller.chat;

import com.athena.chat.dto.chat.MensagemDTO;
import com.athena.chat.model.entities.User;
import com.athena.chat.services.chat.MensagemService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/mensagens")
@RequiredArgsConstructor
@SecurityRequirement(name = "bearerAuth")
public class MensagemController {

    private final MensagemService mensagemService;

    @GetMapping("/chat/{chatId}")
    public ResponseEntity<List<MensagemDTO>> listarMensagens(
            @PathVariable Long chatId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "100") int size,
            @AuthenticationPrincipal User userDetails) {

        Long userId = userDetails.getId();
        List<MensagemDTO> mensagens = mensagemService.listarMensagensPaginado(chatId, userId, page, size);

        return new ResponseEntity<>(mensagens, HttpStatus.OK);
    }

    @PostMapping("/chats/{chatId}/mensagens")
    public ResponseEntity<MensagemDTO> enviarMensagem(
            @PathVariable Long chatId,
            @RequestBody MensagemDTO dto,
            @AuthenticationPrincipal User userDetails) {

        try {
            MensagemDTO mensagemSalva = mensagemService.salvarMensagem(chatId, dto, userDetails.getNome());
            return ResponseEntity.ok(mensagemSalva);

        } catch (IllegalArgumentException e) {

            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        } catch (RuntimeException e) {

            if (e.getCause() instanceof IllegalAccessException) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(null);
            }

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

}

