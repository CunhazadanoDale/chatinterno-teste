package com.athena.chat.services.chat;

import com.athena.chat.dto.chat.AnexoDTO;
import com.athena.chat.model.chat.Anexo;
import com.athena.chat.model.chat.Mensagem;
import com.athena.chat.repositories.AnexoRepository;
import com.athena.chat.services.storage.SupabaseStorageService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AnexoService {

    private final AnexoRepository anexoRepository;
    private final SupabaseStorageService supabaseStorageService;

    /**
     * Cria um anexo e faz upload do arquivo
     */
    @Transactional
    public Anexo criarAnexo(MultipartFile file, Mensagem mensagem, String folder) {
        // Upload para Supabase
        String caminhoSupabase = supabaseStorageService.uploadFile(file, folder);
        String urlPublica = supabaseStorageService.getPublicUrl(caminhoSupabase);

        // Criar entidade Anexo
        Anexo anexo = new Anexo();
        anexo.setMensagem(mensagem);
        anexo.setNomeArquivo(file.getOriginalFilename());
        anexo.setTipoMime(file.getContentType());
        anexo.setTamanhoBytes(file.getSize());
        anexo.setCaminhoSupabase(caminhoSupabase);
        anexo.setUrlPublica(urlPublica);

        return anexoRepository.save(anexo);
    }

    /**
     * Busca anexos de uma mensagem
     */
    public List<AnexoDTO> buscarAnexosPorMensagem(Long mensagemId) {
        List<Anexo> anexos = anexoRepository.findByMensagemId(mensagemId);
        return anexos.stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    /**
     * Deleta um anexo
     */
    @Transactional
    public void deletarAnexo(Long anexoId) {
        Anexo anexo = anexoRepository.findById(anexoId)
                .orElseThrow(() -> new IllegalArgumentException("Anexo não encontrado"));

        // Deletar do Supabase
        supabaseStorageService.deleteFile(anexo.getCaminhoSupabase());

        // Deletar do banco
        anexoRepository.delete(anexo);
    }

    /**
     * Converte Anexo para DTO
     */
    private AnexoDTO convertToDTO(Anexo anexo) {
        AnexoDTO dto = new AnexoDTO();
        dto.setId(anexo.getId());
        dto.setNomeArquivo(anexo.getNomeArquivo());
        dto.setTipoMime(anexo.getTipoMime());
        dto.setTamanhoBytes(anexo.getTamanhoBytes());
        dto.setUrlPublica(anexo.getUrlPublica());
        dto.setUploadedEm(anexo.getUploadedEm().format(DateTimeFormatter.ISO_DATE_TIME));
        return dto;
    }

}
