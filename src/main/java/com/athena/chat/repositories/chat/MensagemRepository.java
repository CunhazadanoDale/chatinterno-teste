package com.athena.chat.repositories.chat;

import com.athena.chat.model.chat.Mensagem;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface MensagemRepository extends JpaRepository<Mensagem, Long> {

    List<Mensagem> findByChatIdOrderByEnviadoEmAsc(Long chatId);
    Page<Mensagem> findByChatIdOrderByEnviadoEmDesc(Long chatId, Pageable pageable);

}
