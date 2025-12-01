package com.athena.chat.repositories.chat;


import com.athena.chat.model.chat.Chat;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ChatRepository extends JpaRepository<Chat, Long> {
    List<Chat> findByParticipantes_Id(Long userId);

    @Query("SELECT c FROM Chat c JOIN c.participantes p1 JOIN c.participantes p2 " +
            "WHERE c.tipo = 'PRIVADO' AND p1.id = :userId1 AND p2.id = :userId2")
    Optional<Chat> findChatPrivadoEntreUsuarios(@Param("userId1") Long userId1,
                                                @Param("userId2") Long userId2);
}

