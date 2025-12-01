package com.athena.chat.repositories;

import com.athena.chat.model.chat.Anexo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AnexoRepository extends JpaRepository<Anexo, Long> {

    List<Anexo> findByMensagemId(Long mensagemId);

}
