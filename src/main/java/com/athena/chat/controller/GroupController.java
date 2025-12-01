package com.athena.chat.controller;

import com.athena.chat.dto.GroupCreateDTO;
import com.athena.chat.dto.GroupDTO;
import com.athena.chat.dto.GroupUpdateDTO;
import com.athena.chat.dto.simpledto.UserSimpleDTO;
import com.athena.chat.model.entities.User;
import com.athena.chat.services.GroupService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/grupos")
@RequiredArgsConstructor
@SecurityRequirement(name = "bearerAuth")
public class GroupController {

    private final GroupService groupService;

    @GetMapping
    public ResponseEntity<List<GroupDTO>> listarGrupos() {
        try {
            List<GroupDTO> grupos = groupService.listarGrupos();

            return new ResponseEntity<>(grupos, HttpStatus.OK);

        } catch (IllegalAccessException e) {
            return ResponseEntity.noContent().build();
        }
    }

    @GetMapping("/meus-grupos")
    public ResponseEntity<List<GroupDTO>> listarGruposDoCriador() {
        List<GroupDTO> grupos = groupService.buscarGruposPorCriador();
        return new ResponseEntity<>(grupos, HttpStatus.OK);
    }

    @GetMapping("/{groupId}")
    public ResponseEntity<GroupDTO> buscarGrupo(@PathVariable Long groupId) {
        GroupDTO dto = groupService.buscarPorId(groupId);
        return ResponseEntity.ok(dto);
    }

    @GetMapping("/{groupId}/usuarios-disponiveis")
    public ResponseEntity<List<UserSimpleDTO>> listarUsuariosDisponiveis(@PathVariable Long groupId) {
        List<UserSimpleDTO> usuarios = groupService.listarUsuariosDisponiveisParaGrupo(groupId);
        return ResponseEntity.ok(usuarios);
    }

    @PutMapping("/{id}")
    public ResponseEntity<GroupDTO> atualizarGrupo(@PathVariable Long id,
                                                   @RequestBody @Valid GroupUpdateDTO dto,
                                                   @AuthenticationPrincipal User userDetails) {
        GroupDTO atualizado = groupService.atualizarGrupo(id, dto, userDetails);
        return ResponseEntity.ok(atualizado);
    }

    @PostMapping
    public ResponseEntity<GroupDTO> criarGrupo(@RequestBody @Valid GroupCreateDTO dto,
                                               @AuthenticationPrincipal User userDetails) {
        GroupDTO grupoCriado = groupService.criarGrupo(dto, userDetails);
        return ResponseEntity.status(HttpStatus.CREATED).body(grupoCriado);
    }

    @PostMapping("/{groupId}/usuarios/{userId}")
    public ResponseEntity<GroupDTO> adicionarUsuarioAoGrupo(@PathVariable Long groupId,
                                                            @PathVariable Long userId) {
        GroupDTO grupoAtualizado = groupService.adicionarUsuarioAoGrupo(groupId, userId);
        return ResponseEntity.ok(grupoAtualizado);
    }

    @DeleteMapping("/{groupId}/usuarios/{userId}")
    public ResponseEntity<GroupDTO> removerUsuarioDoGrupo(@PathVariable Long groupId,
                                                          @PathVariable Long userId) {
        GroupDTO grupoAtualizado = groupService.removerUsuarioDoGrupo(groupId, userId);
        return ResponseEntity.ok(grupoAtualizado);
    }


}
